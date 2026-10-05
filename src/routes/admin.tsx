import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { api, guard, toast, useApp, withStepUp } from '~/client/session'
import { useRemote } from '~/client/useRemote'
import { Page } from '~/components/Shell'
import { EventList, Filters } from '~/components/events'
import type { AuditEvent } from '~/components/events'
import { Badge, Button, PageHeader, Panel, when } from '~/components/ui'

export const Route = createFileRoute('/admin')({ component: Admin })

type User = { id: string; username: string; email: string | null; role: 'member' | 'auditor' | 'admin'; status: 'active' | 'revoked'; devices: number; seen: number | null }
type Analytics = {
  windowMs: number
  epsilonPerMetric: number
  epsilonPerBucket: number
  metrics: Array<{ id: string; label: string; cap: number; noiseScale: number }>
  series: Array<{ start: number; metric: string; value: number }>
}

function Admin() {
  const { me } = useApp()
  const allowed = me!.permissions.includes('audit:read')
  const overview = useRemote<{ events: Array<AuditEvent>; users: Array<User> }>(allowed ? '/api/admin/overview' : '/api/me')
  const analytics = useRemote<Analytics>(allowed ? '/api/admin/analytics' : '/api/me')
  const [filter, setFilter] = useState('all')
  const manage = me!.permissions.includes('account:manage')
  const assign = me!.permissions.includes('role:assign')

  if (!allowed)
    return (
      <Page>
        <PageHeader eyebrow="Administration" title="Not available" description="Your role does not include workspace administration." />
      </Page>
    )

  const act = (work: () => Promise<unknown>, done: string) =>
    guard(async () => {
      await withStepUp(work)
      toast(done)
      await overview.reload()
    })
  const high = overview.data?.events.filter((e) => e.severity === 'high' && e.created > Date.now() - 24 * 3600_000).length ?? 0

  return (
    <Page>
      <PageHeader
        eyebrow={`Administration · ${me!.user.role}`}
        title="Workspace security"
        description="Accounts, the workspace audit trail and private usage statistics. Administrators manage access; they have no way to read conversations."
        actions={high ? <Badge tone="danger">{high} HIGH-SEVERITY IN 24H</Badge> : <Badge tone="good">NO HIGH-SEVERITY SIGNALS</Badge>}
      />

      <Panel title="Accounts" description={manage ? 'Revoking an account signs it out everywhere at once.' : 'Read-only: your role can review but not change accounts.'}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="eyebrow">
              <tr>
                <th className="py-2 pr-4 font-semibold">Account</th>
                <th className="py-2 pr-4 font-semibold">Email</th>
                <th className="py-2 pr-4 font-semibold">Role</th>
                <th className="py-2 pr-4 font-semibold">Devices</th>
                <th className="py-2 pr-4 font-semibold">Last active</th>
                <th className="py-2 font-semibold">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {overview.data?.users.map((u) => {
                const self = u.id === me!.user.id
                return (
                  <tr key={u.id}>
                    <td className="py-3 pr-4 font-medium whitespace-nowrap">
                      @{u.username} {self && <span className="font-normal text-muted">(you)</span>} {u.status === 'revoked' && <Badge tone="danger">REVOKED</Badge>}
                    </td>
                    <td className="py-3 pr-4 whitespace-nowrap text-muted">{u.email ?? '—'}</td>
                    <td className="py-3 pr-4">
                      {assign && !self ? (
                        <select
                          aria-label={`Role for ${u.username}`}
                          value={u.role}
                          onChange={(e) => {
                            // Read now: after a step-up prompt the controlled select has already snapped back.
                            const role = e.target.value
                            void act(() => api('POST', `/api/admin/users/${u.id}/role`, { role }), `@${u.username} is now ${role}.`)
                          }}
                          className="rounded-md border border-line bg-panel px-2 py-1 text-sm"
                        >
                          <option value="member">member</option>
                          <option value="auditor">auditor</option>
                          <option value="admin">admin</option>
                        </select>
                      ) : (
                        u.role
                      )}
                    </td>
                    <td className="py-3 pr-4 tabular-nums">{u.devices}</td>
                    <td className="py-3 pr-4 whitespace-nowrap text-muted">{u.seen ? when(u.seen) : 'never'}</td>
                    <td className="py-3 text-right whitespace-nowrap">
                      {manage && !self && (
                        <span className="inline-flex gap-2">
                          <Button onClick={() => confirm(`Reset device trust for @${u.username}? All of their devices are revoked; their next sign-in enrols a new first device.`) && void act(() => api('POST', `/api/admin/users/${u.id}/reset-devices`, {}), 'Device trust reset.')}>
                            Reset devices
                          </Button>
                          {u.status === 'active' ? (
                            <Button variant="danger" onClick={() => confirm(`Revoke @${u.username}? They are signed out everywhere immediately.`) && void act(() => api('POST', `/api/admin/users/${u.id}/revoke`, {}), 'Account revoked.')}>
                              Revoke
                            </Button>
                          ) : (
                            <Button onClick={() => void act(() => api('POST', `/api/admin/users/${u.id}/restore`, {}), 'Account restored.')}>Restore</Button>
                          )}
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="mt-6">
        <Panel
          title="Usage trends"
          description={
            analytics.data
              ? `Differentially private. Each ${period(analytics.data.windowMs)} is published once with Laplace noise (ε = ${analytics.data.epsilonPerMetric} per metric, ${analytics.data.epsilonPerBucket} per period in total). The current period is not shown until it closes.`
              : 'Loading…'
          }
        >
          {analytics.data && <Trends data={analytics.data} />}
        </Panel>
      </div>

      <div className="mt-6">
        <Panel title="Workspace audit trail" description="Latest 200 events across all accounts" actions={<Filters value={filter} onChange={setFilter} />}>
          {overview.data ? <EventList events={overview.data.events} filter={filter} showUser /> : <p className="py-6 text-center text-sm text-muted">Loading…</p>}
        </Panel>
      </div>
    </Page>
  )
}

const period = (ms: number) => (ms >= 86_400_000 ? 'day' : ms >= 3600_000 ? `${Math.round(ms / 3600_000)}-hour period` : `${Math.round(ms / 60_000)}-minute period`)

/** One small bar chart per metric, sharing the same time axis. */
function Trends({ data }: { data: Analytics }) {
  const starts = [...new Set(data.series.map((p) => p.start))].sort((a, b) => a - b)
  const short = data.windowMs < 86_400_000
  const tick = (start: number) => new Date(start).toLocaleString([], short ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric' })
  if (!starts.length) return <p className="py-6 text-center text-sm text-muted">No closed periods yet.</p>
  return (
    <div className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
      {data.metrics.map((metric) => {
        const points = starts.map((start) => data.series.find((p) => p.start === start && p.metric === metric.id)?.value ?? 0)
        // 95% of pure-noise draws fall below three times the Laplace scale; anything under it may be nothing at all.
        const floor = metric.noiseScale * 3
        const max = Math.max(1, floor * 1.15, ...points)
        const real = points.some((value) => value > floor)
        return (
          <figure key={metric.id}>
            <figcaption className="mb-2 flex items-baseline justify-between gap-2 text-sm">
              <span className="font-medium">{metric.label}</span>
              <span className="text-xs text-muted">counted up to {metric.cap} per person</span>
            </figcaption>
            <div className="relative flex h-24 items-end gap-1 border-b border-line" role="img" aria-label={`${metric.label} per period: ${points.join(', ')}. Values up to ${Math.round(floor)} are within the added noise.`}>
              <div className="pointer-events-none absolute inset-x-0 border-t border-dashed border-muted/50" style={{ bottom: `${(floor / max) * 100}%` }} />
              {points.map((value, i) => (
                <div key={starts[i]} className="group relative flex h-full flex-1 items-end">
                  <div className={`w-full rounded-t transition-colors group-hover:bg-rail ${value > floor ? 'bg-moss' : 'bg-sage-strong'}`} style={{ height: `${Math.max(2, (value / max) * 100)}%` }} />
                  <span className="pointer-events-none absolute -top-6 left-1/2 z-10 hidden -translate-x-1/2 rounded bg-rail px-1.5 py-0.5 text-[11px] whitespace-nowrap text-white group-hover:block">
                    {tick(starts[i])}: {value > floor ? `about ${value}` : 'within noise'}
                  </span>
                </div>
              ))}
            </div>
            <div className="mt-1 flex justify-between text-[11px] text-muted">
              <span>{tick(starts[0])}</span>
              <span>{real ? `dashed line: noise level (${Math.round(floor)})` : 'all within noise — too little activity to measure'}</span>
              <span>{tick(starts.at(-1)!)}</span>
            </div>
          </figure>
        )
      })}
    </div>
  )
}
