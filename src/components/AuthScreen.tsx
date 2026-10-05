import { useState } from 'react'
import { cancelSignIn, completeSignIn, guard, signIn, useApp } from '~/client/session'
import { Button, Field, Qr } from './ui'

export function Logo({ light = false }: { light?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2.5 text-xl font-semibold tracking-tight ${light ? 'text-white' : 'text-ink'}`}>
      <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2 22 12 12 22 2 12Z" fill="none" stroke={light ? '#cbdcb6' : '#3c6a4d'} strokeWidth="2.4" />
        <path d="M12 8.5 15.5 12 12 15.5 8.5 12Z" fill={light ? '#cbdcb6' : '#3c6a4d'} />
      </svg>
      cipherroom
    </span>
  )
}

function defaultLabel() {
  if (typeof navigator === 'undefined') return 'Browser'
  const ua = navigator.userAgent
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser'
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : ''
  return os ? `${browser} on ${os}` : browser
}

export function AuthScreen() {
  const app = useApp()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [label, setLabel] = useState(defaultLabel)

  return (
    <main className="grid min-h-full lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
      <section className="hidden flex-col justify-between bg-rail p-12 text-white lg:flex">
        <Logo light />
        <div>
          <h1 className="max-w-md text-4xl leading-tight font-semibold tracking-tight">Conversations only your devices can read.</h1>
          <ul className="mt-8 space-y-4 text-[15px] text-white/75">
            <li className="flex gap-3">
              <span className="text-sage-strong">◆</span>Messages and files are encrypted on this device with keys that never leave it.
            </li>
            <li className="flex gap-3">
              <span className="text-sage-strong">◆</span>Every message uses a fresh key, so a stolen key cannot unlock past conversations.
            </li>
            <li className="flex gap-3">
              <span className="text-sage-strong">◆</span>Each device proves itself on every request. New devices wait for your approval.
            </li>
          </ul>
        </div>
        <p className="text-xs text-white/50">Coursework prototype. Not independently audited.</p>
      </section>

      <section className="flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Logo />
          </div>
          {app.phase === 'locked' ? (
            <>
              <h2 className="text-2xl font-semibold tracking-tight">{mode === 'login' ? 'Welcome back' : 'Create your account'}</h2>
              <p className="mt-1.5 text-sm text-muted">{mode === 'login' ? 'Unlock the keys stored in this browser.' : 'Your encryption keys are generated on this device.'}</p>
              <div className="mt-6 grid grid-cols-2 rounded-xl bg-sage/70 p-1 text-sm font-medium" role="tablist">
                {(['login', 'register'] as const).map((tab) => (
                  <button key={tab} type="button" role="tab" aria-selected={mode === tab} onClick={() => setMode(tab)} className={`rounded-lg py-2 transition-colors ${mode === tab ? 'bg-panel shadow-sm' : 'text-muted hover:text-ink'}`}>
                    {tab === 'login' ? 'Sign in' : 'Create account'}
                  </button>
                ))}
              </div>
              <form
                className="mt-6 space-y-4"
                onSubmit={(event) => {
                  event.preventDefault()
                  void guard(async () => {
                    await signIn(mode, username, password)
                    setPassword('')
                  })
                }}
              >
                <Field label="Username" name="username" autoComplete="username" required pattern="[a-zA-Z][a-zA-Z0-9_.\-]{2,23}" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="alex.morgan" hint={mode === 'register' ? '3–24 letters, numbers, dots, dashes or underscores.' : undefined} />
                <Field
                  label="Password"
                  name="password"
                  type="password"
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  required
                  minLength={12}
                  maxLength={128}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  hint={mode === 'register' ? 'At least 12 characters. It also encrypts your keys on this device, and it cannot be reset.' : undefined}
                />
                <Button type="submit" variant="primary" className="w-full py-2.5" disabled={app.busy}>
                  {app.busy ? 'Deriving keys…' : mode === 'login' ? 'Continue' : 'Create account'}
                </Button>
              </form>
            </>
          ) : (
            <>
              <h2 className="text-2xl font-semibold tracking-tight">{app.enrol ? 'Set up two-factor sign-in' : 'Enter your code'}</h2>
              <p className="mt-1.5 text-sm text-muted">{app.enrol ? 'Scan this with an authenticator app, then enter the 6-digit code it shows.' : 'Open your authenticator app and enter the current 6-digit code.'}</p>
              {app.enrol && (
                <div className="mt-6 flex items-center gap-4 rounded-xl border border-line bg-panel p-4">
                  <Qr value={app.enrol.uri} size={132} label="Authenticator setup QR code" />
                  <div className="min-w-0 text-sm">
                    <p className="font-medium">Can’t scan?</p>
                    <p className="mt-1 text-muted">Enter this key manually:</p>
                    <code className="mt-2 block font-mono text-xs break-all select-all">{app.enrol.secret}</code>
                  </div>
                </div>
              )}
              <form
                className="mt-6 space-y-4"
                onSubmit={(event) => {
                  event.preventDefault()
                  void guard(async () => {
                    await completeSignIn(code, label)
                    setCode('')
                  })
                }}
              >
                <Field label="Authenticator code" name="code" inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" maxLength={6} placeholder="000000" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
                <Field label="Name this device" name="label" required maxLength={48} value={label} onChange={(e) => setLabel(e.target.value)} hint="Shown in your device list so you can recognise it." />
                <Button type="submit" variant="primary" className="w-full py-2.5" disabled={app.busy}>
                  {app.busy ? 'Verifying…' : 'Verify and continue'}
                </Button>
                <Button variant="ghost" className="w-full" onClick={cancelSignIn}>
                  Back
                </Button>
              </form>
            </>
          )}
        </div>
      </section>
    </main>
  )
}
