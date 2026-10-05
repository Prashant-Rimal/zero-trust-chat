import { createFileRoute } from '@tanstack/react-router'
import { api, getMessenger, guard, lock, toast, useApp, withStepUp } from '~/client/session'
import { useRemote } from '~/client/useRemote'
import { Page } from '~/components/Shell'
import { Badge, Button, PageHeader, Panel, Qr, when } from '~/components/ui'
import { deviceFingerprint } from '~/shared/protocol'

export const Route = createFileRoute('/devices')({ component: Devices })

type Device = { id: string; label: string; ik: string; trust: 'pending' | 'trusted' | 'revoked'; xsig_by: string | null; created: number; seen: number; spk_at: number; current: boolean }
type Session = { id: string; device_id: string; created: number; seen: number; current: boolean; active: boolean; risk: number }

function Devices() {
  useApp()
  const messenger = getMessenger()
  const { data, reload } = useRemote<{ devices: Array<Device>; sessions: Array<Session> }>('/api/devices')
  const act = (work: () => Promise<unknown>, done: string) =>
    guard(async () => {
      await withStepUp(work)
      toast(done)
      await reload()
    })
  const pending = data?.devices.filter((d) => d.trust === 'pending') ?? []
  const labelOf = (id: string) => data?.devices.find((d) => d.id === id)?.label ?? 'Unknown device'

  return (
    <Page>
      <PageHeader
        eyebrow="Zero Trust"
        title="Devices & sessions"
        description="Each device has its own keys and must prove them on every request. A new device can’t read anything until a device you already trust approves it."
      />

      {pending.length > 0 && (
        <div className="mb-6 space-y-3">
          {pending.map((d) => (
            <div key={d.id} role="alert" className="rounded-2xl border border-warn/30 bg-warn-soft p-5">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="font-semibold text-warn">“{d.label}” wants access to your account</p>
                  <p className="mt-1 text-sm text-warn/90">Signed in {when(d.created)} with your password and authenticator code. Approve only if the code below matches what that device shows.</p>
                  <code className="mt-3 inline-block rounded-lg bg-panel px-3 py-1.5 font-mono tracking-widest text-ink">{deviceFingerprint(d.ik)}</code>
                </div>
                <div className="flex gap-2">
                  <Button variant="danger" onClick={() => void act(() => api('POST', `/api/devices/${d.id}/revoke`, {}), 'Device rejected and blocked.')}>
                    Not me — block it
                  </Button>
                  <Button variant="primary" onClick={() => void act(() => messenger.approveDevice(d), 'Device approved and cross-signed.')}>
                    Approve
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_20rem]">
        <div className="space-y-6">
          <Panel title="Your devices">
            <ul className="divide-y divide-line">
              {data?.devices
                .filter((d) => d.trust !== 'pending')
                .map((d) => (
                  <li key={d.id} className="flex flex-wrap items-center gap-3 py-3.5">
                    <div className="min-w-0 flex-1">
                      <p className="flex flex-wrap items-center gap-2 font-medium">
                        {d.label}
                        {d.current && <Badge tone="good">THIS DEVICE</Badge>}
                        {d.trust === 'revoked' ? <Badge tone="danger">REVOKED</Badge> : d.xsig_by ? <Badge>APPROVED BY {labelOf(d.xsig_by).toUpperCase()}</Badge> : <Badge>FIRST DEVICE</Badge>}
                      </p>
                      <p className="mt-0.5 text-xs text-muted">
                        <span className="font-mono">{deviceFingerprint(d.ik)}</span> · added {when(d.created)} · last active {when(d.seen)}
                      </p>
                    </div>
                    {d.trust === 'trusted' && (
                      <Button
                        variant="danger"
                        onClick={() => {
                          if (!confirm(d.current ? 'Revoke this device? You will be signed out and it can never sign in again.' : `Revoke “${d.label}”? It is signed out immediately and can never sign in again.`)) return
                          void act(async () => {
                            await api('POST', `/api/devices/${d.id}/revoke`, {})
                            if (d.current) lock('This device was revoked.')
                          }, 'Device revoked.')
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </li>
                ))}
            </ul>
          </Panel>

          <Panel title="Sessions" description="Sessions end after 8 hours, after 30 minutes without activity, or the moment you end them here.">
            <ul className="divide-y divide-line">
              {data?.sessions.map((s) => (
                <li key={s.id} className="flex items-center gap-3 py-3">
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${s.active ? 'bg-emerald-500' : 'bg-line'}`} aria-hidden="true" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">
                      {labelOf(s.device_id)} {s.current && <span className="text-muted">· this session</span>}
                    </p>
                    <p className="text-xs text-muted">
                      {s.active ? 'Active' : 'Ended'} · started {when(s.created)} · last active {when(s.seen)}
                    </p>
                  </div>
                  {s.risk > 0 && s.active && <Badge tone="warn">CONTEXT CHANGED</Badge>}
                  {s.active && !s.current && <Button onClick={() => void act(() => api('POST', `/api/sessions/${s.id}/revoke`, {}), 'Session ended.')}>End</Button>}
                </li>
              ))}
            </ul>
          </Panel>
        </div>

        <div className="space-y-6">
          <Panel title="Your security code" description="Let a contact scan this, or send them the text below over another channel, so they can verify your keys.">
            <div className="flex flex-col items-center gap-3">
              <Qr value={messenger.verificationCode()} label="Your verification QR code" />
              <code className="w-full rounded-lg bg-sage px-3 py-2 text-center font-mono text-[11px] break-all select-all">{messenger.verificationCode()}</code>
              <Button className="w-full" onClick={() => void guard(async () => (await navigator.clipboard.writeText(messenger.verificationCode()), toast('Code copied.')))}>
                Copy code
              </Button>
            </div>
          </Panel>
          <Panel title="Key rotation" description="Each message already uses a fresh key. Rotating also replaces the prekey that new conversations start from. It happens automatically every 7 days.">
            <Button className="w-full" onClick={() => void guard(async () => (await messenger.rotateKeys(), toast('New signed prekey published.'), await reload()))}>
              Rotate now
            </Button>
            {data && <p className="mt-2 text-center text-xs text-muted">Last rotated {when(data.devices.find((d) => d.current)?.spk_at ?? 0)}</p>}
          </Panel>
        </div>
      </div>
    </Page>
  )
}
