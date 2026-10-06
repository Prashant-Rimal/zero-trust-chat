import { Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { cancelStepUp, dismissToast, getMessenger, guard, logout, resume, submitStepUp, useApp } from '~/client/session'
import { deviceFingerprint } from '~/shared/protocol'
import { AuthScreen, Logo } from './AuthScreen'
import { Badge, Button, Field, Modal } from './ui'

const NAV = [
  { to: '/chat', label: 'Messages', icon: 'M4 5h16v11H9l-5 4z' },
  { to: '/security', label: 'Security', icon: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z' },
  { to: '/devices', label: 'Devices', icon: 'M4 5h16v10H4zM9 19h6M12 15v4' },
  { to: '/privacy', label: 'Privacy', icon: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zm10 3a3 3 0 100-6 3 3 0 000 6z' },
] as const

function Icon({ d }: { d: string }) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  )
}

function Toast() {
  const { toast } = useApp()
  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(dismissToast, 6500)
    return () => clearTimeout(timer)
  }, [toast])
  if (!toast) return null
  return (
    <div role="status" className={`fixed bottom-5 left-1/2 z-50 w-[calc(100%-2rem)] max-w-md -translate-x-1/2 rounded-xl px-4 py-3 text-sm shadow-lg ${toast.error ? 'bg-danger text-white' : 'bg-rail text-white'}`}>
      <div className="flex items-start justify-between gap-3">
        <span>{toast.text}</span>
        <button type="button" onClick={dismissToast} aria-label="Dismiss" className="text-white/70 hover:text-white">
          ×
        </button>
      </div>
    </div>
  )
}

function StepUpDialog() {
  const { stepUp } = useApp()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <Modal open={!!stepUp} title="Confirm it’s you" onClose={cancelStepUp}>
      <p className="mb-4 text-sm text-muted">This is a sensitive action. Enter a fresh code from your authenticator app. The confirmation lasts five minutes.</p>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          setBusy(true)
          void guard(() => submitStepUp(code)).finally(() => {
            setBusy(false)
            setCode('')
          })
        }}
      >
        <Field label="Authenticator code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required placeholder="000000" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
        <div className="flex justify-end gap-2">
          <Button onClick={cancelStepUp}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>
            Verify
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function PendingDevice() {
  const { me } = useApp()
  const fingerprint = deviceFingerprint(getMessenger().keys.ik.pub)
  return (
    <main className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border border-line bg-panel p-8 text-center">
        <Badge tone="warn">WAITING FOR APPROVAL</Badge>
        <h1 className="mt-4 text-2xl font-semibold tracking-tight">Approve this device</h1>
        <p className="mt-2 text-sm text-muted">
          You signed in as <strong className="text-ink">@{me!.user.username}</strong>, but this browser is new. Open Cipherroom on a device you already trust, go to <strong className="text-ink">Devices</strong>, and approve the device showing this code:
        </p>
        <code className="mt-5 block rounded-xl bg-sage px-4 py-3 font-mono text-lg tracking-widest">{fingerprint}</code>
        <p className="mt-4 text-xs text-muted">Until then this device cannot read or send messages. Lost all your other devices? Ask a workspace administrator to reset your device trust.</p>
        <Button className="mt-6" onClick={() => void logout()}>
          Sign out
        </Button>
      </div>
    </main>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const app = useApp()
  useEffect(() => void resume(), [])
  // Holds the sign-in form back until we know whether a reload can reopen the vault by itself.
  if (app.booting) return <main className="h-full" aria-busy="true" />
  if (app.phase !== 'ready' || !app.me)
    return (
      <>
        <AuthScreen />
        <Toast />
      </>
    )
  if (app.me.device.trust === 'pending')
    return (
      <>
        <PendingDevice />
        <Toast />
      </>
    )
  const nav = app.me.permissions.includes('audit:read') ? [...NAV, { to: '/admin' as const, label: 'Admin', icon: 'M12 8a4 4 0 100 8 4 4 0 000-8zM3 12h2M19 12h2M12 3v2M12 19v2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4' }] : NAV
  return (
    <div className="flex h-full flex-col md:flex-row">
      <nav aria-label="Primary" className="order-last flex shrink-0 items-center justify-around bg-rail px-2 py-1.5 text-white/70 md:order-first md:w-56 md:flex-col md:items-stretch md:justify-start md:gap-1 md:p-4">
        <div className="mb-6 hidden px-2 pt-2 md:block">
          <Logo light />
        </div>
        {nav.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            className="flex flex-col items-center gap-1 rounded-lg px-3 py-2 text-[11px] font-medium transition-colors hover:bg-white/10 hover:text-white md:flex-row md:gap-3 md:text-sm"
            activeProps={{ className: 'bg-white/15 text-white' }}
          >
            <Icon d={item.icon} />
            {item.label}
          </Link>
        ))}
        <div className="mt-auto hidden border-t border-white/10 pt-4 md:block">
          <div className="flex items-center gap-2 px-2 text-xs">
            <span className={`h-2 w-2 rounded-full ${app.connection === 'live' ? 'bg-emerald-400' : app.connection === 'connecting' ? 'bg-amber-300' : 'bg-white/30'}`} />
            {app.connection === 'live' ? 'Live connection' : app.connection === 'connecting' ? 'Connecting…' : 'Offline'}
          </div>
          <div className="mt-3 flex items-center justify-between gap-2 px-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-white">@{app.me.user.username}</p>
              <p className="text-[11px] tracking-wider text-white/50 uppercase">{app.me.user.role}</p>
            </div>
            <button type="button" onClick={() => void logout()} className="rounded-lg px-2 py-1.5 text-xs hover:bg-white/10 hover:text-white">
              Sign out
            </button>
          </div>
        </div>
        <button type="button" onClick={() => void logout()} className="flex flex-col items-center gap-1 rounded-lg px-3 py-2 text-[11px] font-medium hover:bg-white/10 hover:text-white md:hidden">
          <Icon d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h9" />
          Sign out
        </button>
      </nav>
      <div className="min-h-0 min-w-0 flex-1">{children}</div>
      <StepUpDialog />
      <Toast />
    </div>
  )
}

export function Page({ children }: { children: ReactNode }) {
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-5 py-8 sm:px-8 sm:py-10">{children}</div>
    </div>
  )
}
