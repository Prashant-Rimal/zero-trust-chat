import { Badge, when } from './ui'

export type AuditEvent = { id: number; kind: string; severity: 'info' | 'warning' | 'high'; detail: Record<string, string | number | boolean>; created: number; username?: string | null }

/** Plain-language names for security events, grouped the way the dashboard filters them. */
export const EVENTS: Record<string, { label: string; group: 'login' | 'session' | 'keys' | 'access' | 'account' }> = {
  'account.created': { label: 'Account created', group: 'account' },
  'session.started': { label: 'Signed in', group: 'login' },
  'login.failed': { label: 'Failed sign-in attempt', group: 'login' },
  'login.bruteforce_suspected': { label: 'Repeated failed sign-ins (possible password guessing)', group: 'login' },
  'login.new_network': { label: 'Sign-in from an unfamiliar network', group: 'login' },
  'mfa.failed': { label: 'Authenticator code rejected', group: 'login' },
  'session.stepup': { label: 'Identity re-confirmed', group: 'session' },
  'session.context_changed': { label: 'Session moved to a different network or browser', group: 'session' },
  'session.risk_revoked': { label: 'Session ended automatically: it looked hijacked', group: 'session' },
  'session.revoked': { label: 'Session ended remotely', group: 'session' },
  'device.enrolled': { label: 'New device signed in', group: 'keys' },
  'device.approved': { label: 'Device approved and cross-signed', group: 'keys' },
  'device.prekey_rotated': { label: 'Encryption prekey rotated', group: 'keys' },
  'device.revoked': { label: 'Device revoked', group: 'keys' },
  'device.reset_by_admin': { label: 'Device trust reset by an administrator', group: 'keys' },
  'device.identity_mismatch': { label: 'Sign-in with a changed or revoked device key blocked', group: 'keys' },
  'message.replay_blocked': { label: 'Replayed message blocked', group: 'access' },
  'access.denied': { label: 'Attempt to reach a conversation without access', group: 'access' },
  'conversation.created': { label: 'Conversation created', group: 'access' },
  'conversation.roster_changed': { label: 'Group members changed', group: 'access' },
  'account.revoked': { label: 'Account revoked', group: 'account' },
  'account.restored': { label: 'Account restored', group: 'account' },
  'role.changed': { label: 'Role changed', group: 'account' },
}

export const GROUPS = [
  { id: 'all', label: 'All' },
  { id: 'login', label: 'Sign-ins' },
  { id: 'session', label: 'Sessions' },
  { id: 'keys', label: 'Keys & devices' },
  { id: 'access', label: 'Access' },
  { id: 'account', label: 'Accounts' },
] as const

export function EventList({ events, filter, showUser = false }: { events: Array<AuditEvent>; filter: string; showUser?: boolean }) {
  const shown = events.filter((e) => filter === 'all' || EVENTS[e.kind]?.group === filter)
  if (!shown.length) return <p className="py-6 text-center text-sm text-muted">Nothing to show for this filter.</p>
  return (
    <ul className="divide-y divide-line">
      {shown.map((e) => (
        <li key={e.id} className="flex items-center gap-3 py-3">
          <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${e.severity === 'high' ? 'bg-danger' : e.severity === 'warning' ? 'bg-warn' : 'bg-sage-strong'}`} aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{EVENTS[e.kind]?.label ?? e.kind}</p>
            <p className="truncate text-xs text-muted">
              {showUser && <>{e.username ? `@${e.username}` : 'unknown account'} · </>}
              {when(e.created)}
              {typeof e.detail.device === 'string' && <> · device {e.detail.device.slice(0, 8)}</>}
            </p>
          </div>
          {e.severity !== 'info' && <Badge tone={e.severity === 'high' ? 'danger' : 'warn'}>{e.severity === 'high' ? 'HIGH' : 'REVIEW'}</Badge>}
        </li>
      ))}
    </ul>
  )
}

export function Filters({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter events">
      {GROUPS.map((g) => (
        <button key={g.id} type="button" aria-pressed={value === g.id} onClick={() => onChange(g.id)} className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${value === g.id ? 'bg-rail text-white' : 'bg-paper text-muted hover:bg-sage'}`}>
          {g.label}
        </button>
      ))}
    </div>
  )
}
