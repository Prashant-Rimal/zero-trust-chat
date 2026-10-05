import { Link, createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useApp } from '~/client/session'
import { useRemote } from '~/client/useRemote'
import { Page } from '~/components/Shell'
import { EventList, Filters } from '~/components/events'
import { EVENTS } from '~/components/events'
import type { AuditEvent } from '~/components/events'
import { PageHeader, Panel, Stat, relative } from '~/components/ui'

export const Route = createFileRoute('/security')({ component: Security })

type Overview = { events: Array<AuditEvent>; stats: { activeSessions: number; trustedDevices: number; pendingDevices: number; alerts: number } }

function Security() {
  const { me } = useApp()
  const { data } = useRemote<Overview>('/api/security')
  const [filter, setFilter] = useState('all')
  const attention = data?.events.filter((e) => e.severity !== 'info' && e.created > Date.now() - 24 * 3600_000) ?? []
  const stepUpFresh = me!.stepUpUntil > Date.now()

  return (
    <Page>
      <PageHeader eyebrow="Your account" title="Security" description="Sign-ins, sessions and key changes on your account. It never includes message content, because the server never has it." />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Active sessions" value={data?.stats.activeSessions ?? '–'} hint="Re-checked on every request" />
        <Stat label="Trusted devices" value={data?.stats.trustedDevices ?? '–'} hint="Hold your encryption keys" />
        <Stat label="Awaiting approval" value={data?.stats.pendingDevices ?? '–'} hint="New devices you have not approved" tone={data?.stats.pendingDevices ? 'warn' : 'neutral'} />
        <Stat label="Signals, last 24h" value={data?.stats.alerts ?? '–'} hint="Warnings worth a look" tone={data?.stats.alerts ? 'warn' : 'neutral'} />
      </div>

      {!!data?.stats.pendingDevices && (
        <p role="alert" className="mt-4 rounded-xl border border-warn/30 bg-warn-soft px-4 py-3 text-sm text-warn">
          A new device signed in with your password and authenticator code and is waiting for approval.{' '}
          <Link to="/devices" className="font-semibold underline">
            Review it in Devices
          </Link>
          . If it wasn’t you, change nothing there and revoke it.
        </p>
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_20rem]">
        <Panel title="Activity" description="Latest 100 events · kept for 30 days" actions={<Filters value={filter} onChange={setFilter} />}>
          {data ? <EventList events={data.events} filter={filter} /> : <p className="py-6 text-center text-sm text-muted">Loading…</p>}
        </Panel>
        <div className="space-y-6">
          <Panel title="Needs attention">
            {attention.length ? (
              <ul className="space-y-2 text-sm">
                {attention.slice(0, 6).map((e) => (
                  <li key={e.id} className={`rounded-lg px-3 py-2 ${e.severity === 'high' ? 'bg-danger-soft text-danger' : 'bg-warn-soft text-warn'}`}>
                    {EVENTS[e.kind]?.label ?? e.kind} · {relative(e.created)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No warnings in the last 24 hours.</p>
            )}
          </Panel>
          <Panel title="This session">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Role</dt>
                <dd className="font-medium capitalize">{me!.user.role}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Device trust</dt>
                <dd className="font-medium capitalize">{me!.device.trust}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Sensitive actions</dt>
                <dd className="font-medium">{stepUpFresh ? `Unlocked, ${relative(me!.stepUpUntil).replace('in ', '')} left` : 'Need your code'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Signs out</dt>
                <dd className="font-medium">{relative(me!.expires)}, or after 30 min idle</dd>
              </div>
            </dl>
          </Panel>
        </div>
      </div>
    </Page>
  )
}
