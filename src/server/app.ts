/**
 * The Cipherroom relay. Framework-agnostic: `handle(Request)` serves the HTTP API and `hub`
 * serves realtime connections. TanStack Start mounts `handle` under /api; tests call it directly.
 *
 * The relay never receives plaintext, private keys, passwords or vault keys. It authenticates
 * devices, enforces membership and device trust on every request and every delivery, queues
 * ciphertext until the recipient device acknowledges it, and records content-free security events.
 */
import { z } from 'zod'
import * as P from '../shared/protocol'
import { digest, hashSecret, networkOf, newTotpSecret, pseudonym, random, sealAtRest, secretMatches, unsealAtRest, verifyTotp } from './crypto'
import { createAnalytics } from './dp'
import type { Db } from './db'

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const SESSION_LIFETIME = 8 * HOUR
const SESSION_IDLE = 30 * MINUTE
const STEP_UP_WINDOW = 5 * MINUTE
const MAX_MESSAGE_LIFETIME = 7 * 24 * HOUR
const CLOCK_SKEW = 2 * MINUTE
const MAX_ATTACHMENT = 8 * 1024 * 1024
const MAX_JSON = 8 * 1024 * 1024
const COOKIE = 'cr_session'

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message)
  }
}
const fail = (status: number, message: string, code?: string): never => {
  throw new HttpError(status, message, code)
}

// ---------- RBAC ----------

export type Role = 'member' | 'auditor' | 'admin'
export type Permission = 'audit:read' | 'analytics:read' | 'account:manage' | 'role:assign'
export const ROLE_PERMISSIONS: Record<Role, ReadonlyArray<Permission>> = {
  member: [],
  auditor: ['audit:read', 'analytics:read'],
  admin: ['audit:read', 'analytics:read', 'account:manage', 'role:assign'],
}
const can = (role: Role, permission: Permission) => ROLE_PERMISSIONS[role].includes(permission)

// ---------- validation ----------

const base64 = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9+/]+={0,2}$/)
const key = z.string().length(44).regex(/^[A-Za-z0-9+/]{43}=$/)
const signature = z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/)
const id = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
const int = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const username = z.string().regex(/^[a-z][a-z0-9_.-]{2,23}$/)
const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
const spkSchema = z.strictObject({ id: int.max(2 ** 31 - 1), pub: key, sig: signature })
const opkSchema = z.strictObject({ id: int.max(2 ** 31 - 1), pub: key })
const rosterSchema = z.strictObject({
  roster: z.strictObject({
    v: z.literal(1),
    conv: id,
    epoch: int.min(1).max(2 ** 31 - 1),
    kind: z.enum(['direct', 'group']),
    owner: id,
    members: z.array(id).min(2).max(50),
  }),
  signer: id,
  sig: signature,
})
const messageSchema = z.strictObject({
  id,
  conv: id,
  created: int,
  expires: int,
  envelopes: z
    .array(
      z.strictObject({
        to: id,
        header: z.strictObject({ dh: key, pn: int.max(2 ** 31), n: int.max(2 ** 31) }),
        pre: z.strictObject({ ek: key, spk: int, opk: int.nullable() }).nullable(),
        nonce: base64(32).length(32),
        ct: base64(44_000),
      }),
    )
    .min(1)
    .max(150),
})
export type OutgoingMessage = z.infer<typeof messageSchema>

// ---------- types ----------

export type Session = {
  hash: string
  userId: string
  username: string
  role: Role
  deviceId: string
  deviceTrust: 'pending' | 'trusted'
  ik: string
  csrf: string
  stepup: number
  created: number
  expires: number
}
type Access = 'public' | 'session' | 'trusted'
type Policy = {
  access: Access
  stepUp?: boolean
  permission?: Permission
  rate?: [max: number, periodMs: number]
  body?: z.ZodType
  binary?: boolean
}
type Ctx<TBody = any> = {
  s: Session
  body: TBody
  params: Record<string, string>
  query: URLSearchParams
  ip: string
  agent: string
  headers: Headers
}
type Route = { method: string; pattern: string; regex: RegExp; keys: Array<string>; policy: Policy; run: (ctx: Ctx) => Promise<unknown> }

export type Connection = {
  hash: string
  userId: string
  deviceId: string
  send: (data: string) => void
  close: (code: number, reason: string) => void
}

export type AppOptions = {
  db: Db
  /** 32 random bytes. Seals TOTP seeds at rest and keys network/agent pseudonyms. */
  secret: Buffer
  origin: string
  epsilon?: number
  analyticsWindowMs?: number
  log?: (line: string) => void
}

export function createApp(options: AppOptions) {
  const { db, secret, origin } = options
  const secure = origin.startsWith('https://')
  const log = options.log ?? ((line: string) => console.log(line))
  const analytics = createAnalytics(db, {
    epsilon: options.epsilon ?? 1,
    windowMs: options.analyticsWindowMs ?? 24 * HOUR,
  })
  const limits = new Map<string, { count: number; until: number }>()
  const connections = new Set<Connection>()
  const routes: Array<Route> = []
  let lastSweep = 0

  const one = async <T = Record<string, any>>(sql: string, params?: Array<unknown>) => (await db.query<T>(sql, params))[0] as T | undefined

  function rate(name: string, max: number, period: number) {
    const now = Date.now()
    const entry = limits.get(name)
    const next = !entry || now > entry.until ? { count: 0, until: now + period } : entry
    next.count++
    limits.set(name, next)
    if (next.count > max) fail(429, 'Too many attempts. Try again later.', 'rate-limited')
  }

  // ---------- audit: event kinds and opaque ids only, never content ----------

  type Severity = 'info' | 'warning' | 'high'
  async function audit(userId: string | null, kind: string, severity: Severity = 'info', detail: Record<string, string | number | boolean> = {}) {
    await db.query(`INSERT INTO audit(user_id, kind, severity, detail, created) VALUES ($1, $2, $3, $4::jsonb, $5)`, [
      userId,
      kind,
      severity,
      JSON.stringify(detail),
      Date.now(),
    ])
    if (userId) {
      if (severity !== 'info') await analytics.record(userId, 'alerts')
      toUser(userId, { t: 'sync', what: 'security' })
    }
  }

  // ---------- realtime hub ----------

  const ALIVE = `SELECT s.hash FROM sessions s JOIN users u ON u.id = s.user_id JOIN devices d ON d.id = s.device_id
    WHERE s.hash = ANY($1) AND NOT s.revoked AND s.expires > $2 AND s.seen > $3 AND u.status = 'active' AND d.trust <> 'revoked'`

  /** Continuous verification for sockets: a connection is only as good as its session is right now. */
  async function deliver(targets: Array<Connection>, event: unknown) {
    if (!targets.length) return
    const now = Date.now()
    const alive = new Set(
      (await db.query<{ hash: string }>(ALIVE, [[...new Set(targets.map((c) => c.hash))], now, now - SESSION_IDLE])).map((r) => r.hash),
    )
    const data = JSON.stringify(event)
    for (const conn of targets) {
      if (alive.has(conn.hash)) conn.send(data)
      else conn.close(4001, 'Session revoked')
    }
  }
  const background = (work: Promise<unknown>) => void work.catch((error) => log(JSON.stringify({ event: 'background-error', name: error?.name })))
  function toUser(userId: string, event: unknown) {
    background(deliver([...connections].filter((c) => c.userId === userId), event))
  }
  function toDevices(deviceIds: Array<string>, make: (deviceId: string) => unknown) {
    for (const deviceId of deviceIds) background(deliver([...connections].filter((c) => c.deviceId === deviceId), make(deviceId)))
  }
  /** Closes every socket whose session, device or account is no longer valid. */
  async function revalidate() {
    await deliver([...connections], { t: 'ping' })
  }

  // ---------- session authentication (runs on every request and socket message) ----------

  const cookieOf = (header: string | null) =>
    (header ?? '')
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${COOKIE}=`))
      ?.slice(COOKIE.length + 1)

  async function authenticate(input: { cookie: string | null; ip: string; agent: string }): Promise<Session> {
    const token = cookieOf(input.cookie)
    if (!token) fail(401, 'Sign in to continue.', 'unauthenticated')
    const now = Date.now()
    const row = await one(
      `SELECT s.*, u.username, u.role, u.status, d.trust, d.ik FROM sessions s
       JOIN users u ON u.id = s.user_id JOIN devices d ON d.id = s.device_id WHERE s.hash = $1`,
      [digest(token!)],
    )
    if (!row || row.revoked || row.status !== 'active' || row.trust === 'revoked' || row.expires < now || row.seen < now - SESSION_IDLE)
      fail(401, 'Session expired or revoked.', 'unauthenticated')
    const s = row!
    let stepup: number = s.stepup
    // The session is bound to the network and browser it was opened from. A change does not end it
    // outright (networks roam) but it withdraws step-up freshness and raises the session's risk.
    const net = pseudonym(networkOf(input.ip), secret)
    const agent = pseudonym(input.agent, secret)
    if (net !== s.net || agent !== s.agent) {
      const risk = s.risk + (net !== s.net ? 1 : 0) + (agent !== s.agent ? 2 : 0)
      if (risk >= 3) {
        await db.query(`UPDATE sessions SET revoked = TRUE WHERE hash = $1`, [s.hash])
        await audit(s.user_id, 'session.risk_revoked', 'high', { device: s.device_id })
        fail(401, 'Session ended because its context changed. Sign in again.', 'unauthenticated')
      }
      stepup = 0
      await db.query(`UPDATE sessions SET net = $1, agent = $2, risk = $3, stepup = 0 WHERE hash = $4`, [net, agent, risk, s.hash])
      await audit(s.user_id, 'session.context_changed', 'warning', { device: s.device_id, network: net !== s.net, browser: agent !== s.agent })
    }
    if (s.seen < now - 20_000) {
      await db.query(`UPDATE sessions SET seen = $1 WHERE hash = $2`, [now, s.hash])
      await db.query(`UPDATE devices SET seen = $1 WHERE id = $2`, [now, s.device_id])
    }
    return {
      hash: s.hash,
      userId: s.user_id,
      username: s.username,
      role: s.role,
      deviceId: s.device_id,
      deviceTrust: s.trust,
      ik: s.ik,
      csrf: s.csrf,
      stepup,
      created: s.created,
      expires: s.expires,
    }
  }

  function authorize(s: Session, policy: Policy) {
    if (policy.access === 'trusted' && s.deviceTrust !== 'trusted')
      fail(403, 'This device is waiting for approval from one of your trusted devices.', 'device-pending')
    if (policy.permission && !can(s.role, policy.permission)) fail(403, 'Your role does not allow this.', 'forbidden')
    if (policy.stepUp && s.stepup < Date.now() - STEP_UP_WINDOW)
      fail(403, 'Confirm your authenticator code to continue.', 'step-up-required')
  }

  // ---------- helpers shared by routes ----------

  async function requireMember(conv: string, s: Session) {
    if (!(await one(`SELECT 1 FROM members WHERE conv = $1 AND user_id = $2`, [conv, s.userId]))) {
      await audit(s.userId, 'access.denied', 'warning', { device: s.deviceId })
      fail(403, 'You are not a member of this conversation.', 'forbidden')
    }
  }
  const trustedDevices = (conv: string) =>
    db.query<{ id: string; user_id: string }>(
      `SELECT d.id, d.user_id FROM devices d JOIN members m ON m.user_id = d.user_id JOIN users u ON u.id = d.user_id
       WHERE m.conv = $1 AND d.trust = 'trusted' AND u.status = 'active'`,
      [conv],
    )

  async function useTotp(userId: string, code: unknown) {
    const user = (await one(`SELECT totp, totp_step FROM users WHERE id = $1`, [userId]))!
    const step = verifyTotp(unsealAtRest(user.totp, secret), code, user.totp_step)
    if (step === null) {
      await audit(userId, 'mfa.failed', 'warning')
      fail(401, 'Invalid or already used authenticator code. Wait for a new code.', 'bad-code')
    }
    await db.query(`UPDATE users SET totp_step = $1 WHERE id = $2`, [step, userId])
  }

  async function revokeSessions(where: string, value: string) {
    await db.query(`UPDATE sessions SET revoked = TRUE WHERE ${where} = $1`, [value])
    await revalidate()
  }

  /** Shared by the HTTP route and the WebSocket `send` frame. */
  async function sendMessage(s: Session, message: OutgoingMessage) {
    const now = Date.now()
    await requireMember(message.conv, s)
    if (Math.abs(now - message.created) > CLOCK_SKEW) fail(400, 'Message timestamp is outside the accepted window.', 'stale')
    if (message.expires <= now || message.expires > message.created + MAX_MESSAGE_LIFETIME) fail(400, 'Invalid message lifetime.')
    const allowed = new Set((await trustedDevices(message.conv)).map((d) => d.id))
    const recipients = message.envelopes.map((e) => e.to)
    if (new Set(recipients).size !== recipients.length || recipients.some((to) => to === s.deviceId || !allowed.has(to)))
      fail(409, 'Recipient devices changed. Refresh and retry.', 'recipients-changed')
    try {
      await db.tx(async (tx) => {
        for (const e of message.envelopes) {
          const inserted = await tx.query(`INSERT INTO replays(hash, expires) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING hash`, [
            digest(`${message.id}|${e.to}`),
            message.expires + HOUR,
          ])
          if (!inserted.length) throw new HttpError(409, 'Replay rejected.', 'replay')
          const envelope: P.Envelope = {
            id: message.id,
            conv: message.conv,
            from: s.deviceId,
            to: e.to,
            created: message.created,
            expires: message.expires,
            header: e.header,
            pre: e.pre,
            nonce: e.nonce,
            ct: e.ct,
          }
          await tx.query(`INSERT INTO envelopes(id, recipient, conv, body, created, expires) VALUES ($1, $2, $3, $4, $5, $6)`, [
            message.id,
            e.to,
            message.conv,
            JSON.stringify(envelope),
            message.created,
            message.expires,
          ])
        }
      })
    } catch (error) {
      if (error instanceof HttpError && error.code === 'replay') await audit(s.userId, 'message.replay_blocked', 'warning', { device: s.deviceId })
      throw error
    }
    await analytics.record(s.userId, 'messages')
    toDevices(recipients, (to) => {
      const e = message.envelopes.find((x) => x.to === to)!
      return { t: 'envelope', e: { id: message.id, conv: message.conv, from: s.deviceId, to, created: message.created, expires: message.expires, header: e.header, pre: e.pre, nonce: e.nonce, ct: e.ct } }
    })
    return { id: message.id, delivered: recipients.length }
  }

  const acknowledge = (s: Session, ids: Array<string>) =>
    db.query(`DELETE FROM envelopes WHERE recipient = $1 AND id = ANY($2)`, [s.deviceId, ids])

  // ---------- routing ----------

  function route<TBody = any>(method: string, pattern: string, policy: Policy, run: (ctx: Ctx<TBody>) => Promise<unknown>) {
    const keys: Array<string> = []
    const regex = new RegExp(`^${pattern.replace(/:(\w+)/g, (_, name) => (keys.push(name), '([\\w-]{1,64})'))}$`)
    routes.push({ method, pattern, regex, keys, policy, run })
  }

  async function createSession(headers: Headers, userId: string, deviceId: string, ip: string, agent: string) {
    const token = random()
    const csrf = random()
    const now = Date.now()
    await db.query(
      `INSERT INTO sessions(hash, user_id, device_id, csrf, created, expires, seen, stepup, net, agent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [digest(token), userId, deviceId, csrf, now, now + SESSION_LIFETIME, now, now, pseudonym(networkOf(ip), secret), pseudonym(agent, secret)],
    )
    headers.append('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME / 1000}${secure ? '; Secure' : ''}`)
    return csrf
  }

  const me = (s: Session) => ({
    user: { id: s.userId, username: s.username, role: s.role },
    device: { id: s.deviceId, trust: s.deviceTrust },
    csrf: s.csrf,
    permissions: ROLE_PERMISSIONS[s.role],
    stepUpUntil: s.stepup + STEP_UP_WINDOW,
    expires: s.expires,
  })

  // ----- authentication -----

  route<{ username: string; email: string; authKey: string }>(
    'POST',
    '/api/auth/register',
    { access: 'public', body: z.strictObject({ username, email, authKey: key }) },
    async ({ body, ip }) => {
      rate(`register:${ip}`, 10, HOUR)
      if (await one(`SELECT 1 FROM users WHERE username = $1`, [body.username])) fail(409, 'Username unavailable.')
      const userId = P.uuid()
      const totpSecret = newTotpSecret()
      const challenge = random()
      const now = Date.now()
      await db.query(`INSERT INTO users(id, username, email, auth_hash, totp, created) VALUES ($1, $2, $3, $4, $5, $6)`, [
        userId,
        body.username,
        body.email,
        await hashSecret(body.authKey),
        sealAtRest(totpSecret, secret),
        now,
      ])
      await db.query(`INSERT INTO challenges(hash, user_id, enroll, expires) VALUES ($1, $2, TRUE, $3)`, [digest(challenge), userId, now + 10 * MINUTE])
      return {
        challenge,
        secret: totpSecret,
        uri: `otpauth://totp/Cipherroom:${body.username}?secret=${totpSecret}&issuer=Cipherroom&algorithm=SHA1&digits=6&period=30`,
      }
    },
  )

  route<{ username: string; authKey: string }>(
    'POST',
    '/api/auth/login',
    { access: 'public', body: z.strictObject({ username, authKey: key }) },
    async ({ body, ip }) => {
      rate(`login-ip:${ip}`, 30, 5 * MINUTE)
      rate(`login:${body.username}`, 10, 5 * MINUTE)
      const user = await one(`SELECT id, auth_hash, status FROM users WHERE username = $1`, [body.username])
      // Hash even for unknown users so response time does not reveal whether the account exists.
      const valid = user ? await secretMatches(body.authKey, user.auth_hash) : (await hashSecret(body.authKey), false)
      if (!user || !valid || user.status !== 'active') {
        const now = Date.now()
        await audit(user?.id ?? null, 'login.failed', 'warning')
        if (user) {
          const [{ n }] = await db.query<{ n: number }>(
            `SELECT COUNT(*)::int AS n FROM audit WHERE user_id = $1 AND kind = 'login.failed' AND created > $2`,
            [user.id, now - 10 * MINUTE],
          )
          const flagged = await one(`SELECT 1 FROM audit WHERE user_id = $1 AND kind = 'login.bruteforce_suspected' AND created > $2`, [user.id, now - 10 * MINUTE])
          if (n >= 5 && !flagged) await audit(user.id, 'login.bruteforce_suspected', 'high', { attempts: n })
        }
        fail(401, 'Invalid credentials or account unavailable.', 'bad-credentials')
      }
      const challenge = random()
      await db.query(`INSERT INTO challenges(hash, user_id, enroll, expires) VALUES ($1, $2, FALSE, $3)`, [digest(challenge), user!.id, Date.now() + 5 * MINUTE])
      return { challenge }
    },
  )

  type VerifyBody = {
    challenge: string
    code: string
    device: { id: string; label: string; ik: string; dh: string; dhSig: string }
    spk: z.infer<typeof spkSchema>
    opks: Array<z.infer<typeof opkSchema>>
    proof: string
  }
  route<VerifyBody>(
    'POST',
    '/api/auth/verify',
    {
      access: 'public',
      body: z.strictObject({
        challenge: z.string().min(20).max(64),
        code: z.string().max(12),
        device: z.strictObject({ id, label: z.string().trim().min(1).max(48), ik: key, dh: key, dhSig: signature }),
        spk: spkSchema,
        opks: z.array(opkSchema).max(100),
        proof: signature,
      }),
    },
    async ({ body, ip, agent, headers }) => {
      rate(`mfa:${ip}`, 20, 5 * MINUTE)
      const now = Date.now()
      const challengeHash = digest(body.challenge)
      const challenge = await one(`SELECT user_id, enroll, expires FROM challenges WHERE hash = $1`, [challengeHash])
      if (!challenge || challenge.expires < now) fail(401, 'Sign-in challenge expired. Start again.', 'challenge-expired')
      const user = (await one(`SELECT id, username, role, status FROM users WHERE id = $1`, [challenge!.user_id]))!
      if (user.status === 'revoked') fail(401, 'Account revoked.')
      const d = body.device
      // Possession of the device identity key is a login factor alongside the password and TOTP.
      if (!P.verifyDhCert(d) || !P.verifySpk(d.id, d.ik, body.spk) || !P.verifyLogin(d.ik, body.challenge, d.id, body.proof))
        fail(400, 'Device key proof is invalid.', 'bad-proof')
      const existing = await one(`SELECT user_id, ik, trust FROM devices WHERE id = $1`, [d.id])
      if (existing && (existing.user_id !== user.id || existing.ik !== d.ik || existing.trust === 'revoked')) {
        await audit(user.id, 'device.identity_mismatch', 'high', { device: d.id })
        fail(403, 'This device was revoked or its identity key changed.', 'device-rejected')
      }
      await useTotp(user.id, body.code)
      await db.query(`DELETE FROM challenges WHERE hash = $1`, [challengeHash])

      if (challenge!.enroll) {
        // The first account to finish MFA enrolment bootstraps the workspace as its administrator.
        const admin = await one(`SELECT 1 FROM users WHERE role = 'admin' AND status = 'active'`)
        user.role = admin ? 'member' : 'admin'
        await db.query(`UPDATE users SET status = 'active', role = $1 WHERE id = $2`, [user.role, user.id])
        await audit(user.id, 'account.created', 'info')
      }
      let trust: 'pending' | 'trusted' = existing?.trust
      if (!existing) {
        const hasTrusted = await one(`SELECT 1 FROM devices WHERE user_id = $1 AND trust = 'trusted'`, [user.id])
        // Least privilege for new devices: password + TOTP alone do not make a device trusted when
        // the account already has one. An existing trusted device must vouch for it.
        trust = hasTrusted ? 'pending' : 'trusted'
        await db.query(
          `INSERT INTO devices(id, user_id, label, ik, dh, dh_sig, spk_id, spk, spk_sig, spk_at, trust, created, seen)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10,$10)`,
          [d.id, user.id, d.label, d.ik, d.dh, d.dhSig, body.spk.id, body.spk.pub, body.spk.sig, now, trust],
        )
        for (const opk of body.opks) await db.query(`INSERT INTO prekeys(device_id, id, pub) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [d.id, opk.id, opk.pub])
        await audit(user.id, 'device.enrolled', 'warning', { device: d.id, trust })
        toUser(user.id, { t: 'sync', what: 'devices' })
      }
      const net = pseudonym(networkOf(ip), secret)
      const known = await one(`SELECT 1 FROM sessions WHERE user_id = $1 LIMIT 1`, [user.id])
      if (known && !(await one(`SELECT 1 FROM sessions WHERE user_id = $1 AND net = $2 LIMIT 1`, [user.id, net])))
        await audit(user.id, 'login.new_network', 'warning', { device: d.id })
      const csrf = await createSession(headers, user.id, d.id, ip, agent)
      await audit(user.id, 'session.started', 'info', { device: d.id })
      await analytics.record(user.id, 'logins')
      return {
        user: { id: user.id, username: user.username, role: user.role },
        device: { id: d.id, trust },
        csrf,
        permissions: ROLE_PERMISSIONS[user.role as Role],
        stepUpUntil: now + STEP_UP_WINDOW,
        expires: now + SESSION_LIFETIME,
      }
    },
  )

  route('GET', '/api/me', { access: 'session' }, async ({ s }) => me(s))

  route('POST', '/api/auth/logout', { access: 'session' }, async ({ s, headers }) => {
    await revokeSessions('hash', s.hash)
    headers.append('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`)
    return { ok: true }
  })

  route<{ code: string }>('POST', '/api/auth/stepup', { access: 'session', body: z.strictObject({ code: z.string().max(12) }) }, async ({ s, body }) => {
    rate(`stepup:${s.userId}`, 6, 5 * MINUTE)
    await useTotp(s.userId, body.code)
    const now = Date.now()
    await db.query(`UPDATE sessions SET stepup = $1, risk = 0 WHERE hash = $2`, [now, s.hash])
    await audit(s.userId, 'session.stepup', 'info', { device: s.deviceId })
    return { stepUpUntil: now + STEP_UP_WINDOW }
  })

  // ----- directory -----

  route('GET', '/api/users', { access: 'trusted', rate: [60, MINUTE] }, async ({ s, query }) => {
    const q = (query.get('q') ?? '').toLowerCase()
    // Prefix search with a minimum length, so the member list cannot be dumped in one call.
    if (!/^[a-z0-9_.-]{2,24}$/.test(q)) return []
    return db.query(`SELECT id, username FROM users WHERE status = 'active' AND id <> $1 AND username LIKE $2 ORDER BY username LIMIT 10`, [
      s.userId,
      `${q.replace(/[_%\\]/g, '\\$&')}%`,
    ])
  })

  route('GET', '/api/conversations', { access: 'trusted' }, async ({ s }) =>
    db.query(
      `SELECT c.id, c.kind, c.created, c.roster, c.signer, c.sig FROM conversations c JOIN members m ON m.conv = c.id
       WHERE m.user_id = $1 ORDER BY c.created DESC`,
      [s.userId],
    ),
  )

  route<P.SignedRoster>('POST', '/api/conversations', { access: 'trusted', body: rosterSchema, rate: [30, HOUR] }, async ({ s, body }) => {
    const { roster } = body
    const members = [...new Set(roster.members)].sort()
    if (body.signer !== s.deviceId || roster.owner !== s.userId || roster.epoch !== 1 || !members.includes(s.userId))
      fail(400, 'Roster must be created and signed by its owner on this device.')
    if (members.length !== roster.members.length || (roster.kind === 'direct' && members.length !== 2)) fail(400, 'Invalid participants.')
    if (!P.verifyRoster(body, s.ik)) fail(400, 'Roster signature is invalid.', 'bad-signature')
    const active = await db.query(`SELECT id FROM users WHERE id = ANY($1) AND status = 'active'`, [members])
    if (active.length !== members.length) fail(400, 'A participant is unavailable.')
    if (roster.kind === 'direct') {
      const existing = await one(
        `SELECT c.id FROM conversations c JOIN members a ON a.conv = c.id AND a.user_id = $1 JOIN members b ON b.conv = c.id AND b.user_id = $2 WHERE c.kind = 'direct'`,
        members,
      )
      if (existing) return { id: existing.id, existing: true }
    }
    if (await one(`SELECT 1 FROM conversations WHERE id = $1`, [roster.conv])) fail(409, 'Conversation id already exists.')
    await db.tx(async (tx) => {
      await tx.query(`INSERT INTO conversations(id, kind, owner, epoch, roster, signer, sig, created) VALUES ($1,$2,$3,1,$4::jsonb,$5,$6,$7)`, [
        roster.conv,
        roster.kind,
        s.userId,
        JSON.stringify({ ...roster, members }),
        body.signer,
        body.sig,
        Date.now(),
      ])
      for (const userId of members) await tx.query(`INSERT INTO members(conv, user_id) VALUES ($1, $2)`, [roster.conv, userId])
    })
    await audit(s.userId, 'conversation.created', 'info', { kind: roster.kind })
    for (const userId of members) toUser(userId, { t: 'sync', what: 'conversations' })
    return { id: roster.conv, existing: false }
  })

  // Membership changes are a sensitive action: owner only, fresh second factor, signed by the owner's device.
  route<P.SignedRoster>(
    'PUT',
    '/api/conversations/:id/roster',
    { access: 'trusted', stepUp: true, body: rosterSchema },
    async ({ s, body, params }) => {
      const conv = await one(`SELECT kind, owner, epoch FROM conversations WHERE id = $1`, [params.id])
      if (!conv || conv.owner !== s.userId) {
        await audit(s.userId, 'access.denied', 'warning', { device: s.deviceId })
        fail(403, 'Only the conversation owner can change its members.', 'forbidden')
      }
      const { roster } = body
      const members = [...new Set(roster.members)].sort()
      if (conv!.kind !== 'group' || roster.kind !== 'group') fail(400, 'Direct conversations have fixed participants.')
      if (roster.conv !== params.id || roster.owner !== s.userId || roster.epoch !== conv!.epoch + 1 || body.signer !== s.deviceId || !members.includes(s.userId))
        fail(409, 'Roster is out of date. Refresh and retry.', 'stale-roster')
      if (members.length !== roster.members.length || !P.verifyRoster(body, s.ik)) fail(400, 'Roster signature is invalid.', 'bad-signature')
      const active = await db.query(`SELECT id FROM users WHERE id = ANY($1) AND status = 'active'`, [members])
      if (active.length !== members.length) fail(400, 'A participant is unavailable.')
      const before = (await db.query<{ user_id: string }>(`SELECT user_id FROM members WHERE conv = $1`, [params.id])).map((m) => m.user_id)
      const removed = before.filter((userId) => !members.includes(userId))
      await db.tx(async (tx) => {
        await tx.query(`UPDATE conversations SET epoch = $1, roster = $2::jsonb, signer = $3, sig = $4 WHERE id = $5`, [
          roster.epoch,
          JSON.stringify({ ...roster, members }),
          body.signer,
          body.sig,
          params.id,
        ])
        await tx.query(`DELETE FROM members WHERE conv = $1`, [params.id])
        for (const userId of members) await tx.query(`INSERT INTO members(conv, user_id) VALUES ($1, $2)`, [params.id, userId])
        // Ciphertext still queued for a removed member is discarded, not delivered late.
        if (removed.length)
          await tx.query(`DELETE FROM envelopes WHERE conv = $1 AND recipient IN (SELECT id FROM devices WHERE user_id = ANY($2))`, [params.id, removed])
      })
      await audit(s.userId, 'conversation.roster_changed', 'warning', { added: members.length - (before.length - removed.length), removed: removed.length })
      for (const userId of new Set([...before, ...members])) toUser(userId, { t: 'sync', what: 'conversations' })
      return { epoch: roster.epoch }
    },
  )

  route('GET', '/api/conversations/:id/directory', { access: 'trusted' }, async ({ s, params }) => {
    await requireMember(params.id, s)
    const users = await db.query(`SELECT u.id, u.username FROM users u JOIN members m ON m.user_id = u.id WHERE m.conv = $1`, [params.id])
    // Revoked devices stay listed (flagged) so signatures they made while trusted can still be checked.
    const devices = await db.query(
      `SELECT d.id, d.user_id, d.label, d.ik, d.dh, d.dh_sig, d.trust, d.xsig_by, d.xsig, d.created FROM devices d
       JOIN members m ON m.user_id = d.user_id JOIN users u ON u.id = d.user_id
       WHERE m.conv = $1 AND d.trust <> 'pending' ORDER BY d.created`,
      [params.id],
    )
    return {
      users,
      devices: devices.map(
        (d): P.PublicDevice => ({
          id: d.id,
          userId: d.user_id,
          label: d.label,
          ik: d.ik,
          dh: d.dh,
          dhSig: d.dh_sig,
          trust: d.trust,
          xsig: d.xsig ? { by: d.xsig_by, sig: d.xsig } : null,
          created: d.created,
        }),
      ),
    }
  })

  // ----- prekeys -----

  route('POST', '/api/devices/:id/bundle', { access: 'trusted', rate: [120, MINUTE] }, async ({ s, params }): Promise<P.PrekeyBundle> => {
    // Only someone who shares a conversation with the device's owner may take one of its prekeys.
    const device = await one(
      `SELECT d.spk_id, d.spk, d.spk_sig FROM devices d JOIN members m1 ON m1.user_id = d.user_id JOIN members m2 ON m2.conv = m1.conv
       WHERE d.id = $1 AND m2.user_id = $2 AND d.trust = 'trusted' LIMIT 1`,
      [params.id, s.userId],
    )
    if (!device) fail(404, 'Device not found.')
    const opk = await one(
      `DELETE FROM prekeys WHERE device_id = $1 AND id = (SELECT id FROM prekeys WHERE device_id = $1 ORDER BY id LIMIT 1) RETURNING id, pub`,
      [params.id],
    )
    return { spk: { id: device!.spk_id, pub: device!.spk, sig: device!.spk_sig }, opk: opk ? { id: opk.id, pub: opk.pub } : null }
  })

  route<{ spk?: z.infer<typeof spkSchema>; opks: Array<z.infer<typeof opkSchema>> }>(
    'POST',
    '/api/prekeys',
    { access: 'trusted', body: z.strictObject({ spk: spkSchema.optional(), opks: z.array(opkSchema).max(100) }) },
    async ({ s, body }) => {
      if (body.spk) {
        if (!P.verifySpk(s.deviceId, s.ik, body.spk)) fail(400, 'Signed prekey signature is invalid.', 'bad-signature')
        const updated = await db.query(`UPDATE devices SET spk_id = $1, spk = $2, spk_sig = $3, spk_at = $4 WHERE id = $5 AND spk_id < $1 RETURNING id`, [
          body.spk.id,
          body.spk.pub,
          body.spk.sig,
          Date.now(),
          s.deviceId,
        ])
        if (!updated.length) fail(409, 'Signed prekey id must increase.')
        await audit(s.userId, 'device.prekey_rotated', 'info', { device: s.deviceId })
      }
      for (const opk of body.opks) await db.query(`INSERT INTO prekeys(device_id, id, pub) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [s.deviceId, opk.id, opk.pub])
      const [{ n }] = await db.query<{ n: number }>(`SELECT COUNT(*)::int AS n FROM prekeys WHERE device_id = $1`, [s.deviceId])
      return { available: n }
    },
  )

  route('GET', '/api/prekeys', { access: 'trusted' }, async ({ s }) => {
    const [{ n }] = await db.query<{ n: number }>(`SELECT COUNT(*)::int AS n FROM prekeys WHERE device_id = $1`, [s.deviceId])
    const device = (await one(`SELECT spk_id, spk_at FROM devices WHERE id = $1`, [s.deviceId]))!
    return { available: n, spkId: device.spk_id, spkAt: device.spk_at }
  })

  // ----- messages -----

  route<OutgoingMessage>('POST', '/api/messages', { access: 'trusted', body: messageSchema, rate: [300, MINUTE] }, ({ s, body }) => sendMessage(s, body))

  route('GET', '/api/messages', { access: 'trusted' }, async ({ s }) =>
    (
      await db.query<{ body: string }>(`SELECT body FROM envelopes WHERE recipient = $1 AND expires > $2 ORDER BY created, id LIMIT 500`, [s.deviceId, Date.now()])
    ).map((row) => JSON.parse(row.body)),
  )

  route<{ ids: Array<string> }>('POST', '/api/messages/ack', { access: 'trusted', body: z.strictObject({ ids: z.array(id).max(500) }) }, async ({ s, body }) => {
    await acknowledge(s, body.ids)
    return { ok: true }
  })

  route<Uint8Array>('POST', '/api/conversations/:id/attachments', { access: 'trusted', binary: true, rate: [30, MINUTE] }, async ({ s, body, params, query }) => {
    await requireMember(params.id, s)
    const now = Date.now()
    const expires = Number(query.get('expires'))
    if (!Number.isSafeInteger(expires) || expires <= now || expires > now + MAX_MESSAGE_LIFETIME + CLOCK_SKEW) fail(400, 'Invalid attachment lifetime.')
    if (!body.length) fail(400, 'Empty attachment.')
    const attachmentId = P.uuid()
    await db.query(`INSERT INTO attachments(id, conv, data, size, created, expires) VALUES ($1, $2, $3, $4, $5, $6)`, [attachmentId, params.id, body, body.length, now, expires])
    await analytics.record(s.userId, 'attachments')
    return { id: attachmentId }
  })

  route('GET', '/api/attachments/:id', { access: 'trusted' }, async ({ s, params }) => {
    const row = await one(`SELECT conv, data FROM attachments WHERE id = $1 AND expires > $2`, [params.id, Date.now()])
    if (!row) fail(404, 'Attachment not found or expired.')
    await requireMember(row!.conv, s)
    return new Response(new Uint8Array(row!.data), { headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment' } })
  })

  // ----- devices and sessions -----

  route('GET', '/api/devices', { access: 'session' }, async ({ s }) => {
    const devices = await db.query(`SELECT id, label, ik, trust, xsig_by, created, seen, spk_at FROM devices WHERE user_id = $1 ORDER BY created DESC`, [s.userId])
    const now = Date.now()
    const sessions = await db.query(
      `SELECT substr(hash, 1, 16) AS id, device_id, created, expires, seen, revoked, risk FROM sessions WHERE user_id = $1 ORDER BY created DESC LIMIT 30`,
      [s.userId],
    )
    return {
      devices: devices.map((d) => ({ ...d, current: d.id === s.deviceId })),
      sessions: sessions.map((x) => ({ ...x, current: x.id === s.hash.slice(0, 16), active: !x.revoked && x.expires > now && x.seen > now - SESSION_IDLE })),
    }
  })

  route<{ sig: string }>(
    'POST',
    '/api/devices/:id/approve',
    { access: 'trusted', stepUp: true, body: z.strictObject({ sig: signature }) },
    async ({ s, body, params }) => {
      const target = await one(`SELECT ik, trust FROM devices WHERE id = $1 AND user_id = $2`, [params.id, s.userId])
      if (!target || target.trust !== 'pending') fail(404, 'No pending device with that id.')
      if (!P.verifyCrossSign(s.ik, s.userId, params.id, target!.ik, body.sig)) fail(400, 'Approval signature is invalid.', 'bad-signature')
      await db.query(`UPDATE devices SET trust = 'trusted', xsig_by = $1, xsig = $2 WHERE id = $3`, [s.deviceId, body.sig, params.id])
      await audit(s.userId, 'device.approved', 'warning', { device: params.id, by: s.deviceId })
      toUser(s.userId, { t: 'sync', what: 'devices' })
      return { ok: true }
    },
  )

  async function revokeDevice(actor: Session, deviceId: string, kind = 'device.revoked') {
    await db.query(`UPDATE devices SET trust = 'revoked' WHERE id = $1`, [deviceId])
    await db.query(`DELETE FROM prekeys WHERE device_id = $1`, [deviceId])
    await db.query(`DELETE FROM envelopes WHERE recipient = $1`, [deviceId])
    await audit(actor.userId, kind, 'high', { device: deviceId })
    await revokeSessions('device_id', deviceId)
  }

  route('POST', '/api/devices/:id/revoke', { access: 'trusted', stepUp: true }, async ({ s, params }) => {
    const target = await one(`SELECT trust FROM devices WHERE id = $1 AND user_id = $2`, [params.id, s.userId])
    if (!target || target.trust === 'revoked') fail(404, 'Device not found.')
    await revokeDevice(s, params.id)
    toUser(s.userId, { t: 'sync', what: 'devices' })
    return { ok: true }
  })

  route('POST', '/api/sessions/:id/revoke', { access: 'trusted', stepUp: true }, async ({ s, params }) => {
    const target = await one(`SELECT hash FROM sessions WHERE user_id = $1 AND substr(hash, 1, 16) = $2`, [s.userId, params.id])
    if (!target) fail(404, 'Session not found.')
    await audit(s.userId, 'session.revoked', 'warning')
    await revokeSessions('hash', target!.hash)
    return { ok: true }
  })

  // ----- security dashboard -----

  route('GET', '/api/security', { access: 'session' }, async ({ s }) => {
    const now = Date.now()
    const events = await db.query(`SELECT id, kind, severity, detail, created FROM audit WHERE user_id = $1 ORDER BY id DESC LIMIT 100`, [s.userId])
    const [{ n: activeSessions }] = await db.query<{ n: number }>(ALIVE.replace('SELECT s.hash', 'SELECT COUNT(*)::int AS n').replace('s.hash = ANY($1)', 's.user_id = $1'), [
      s.userId,
      now,
      now - SESSION_IDLE,
    ])
    const devices = await db.query<{ trust: string; n: number }>(`SELECT trust, COUNT(*)::int AS n FROM devices WHERE user_id = $1 GROUP BY trust`, [s.userId])
    const count = (trust: string) => devices.find((d) => d.trust === trust)?.n ?? 0
    return {
      events,
      stats: {
        activeSessions,
        trustedDevices: count('trusted'),
        pendingDevices: count('pending'),
        alerts: events.filter((e) => e.severity !== 'info' && e.created > now - 24 * HOUR).length,
      },
    }
  })

  route('GET', '/api/admin/overview', { access: 'trusted', permission: 'audit:read' }, async () => {
    const events = await db.query(
      `SELECT a.id, a.kind, a.severity, a.detail, a.created, u.username FROM audit a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 200`,
    )
    const users = await db.query(
      `SELECT u.id, u.username, u.email, u.role, u.status, u.created,
        (SELECT COUNT(*)::int FROM devices d WHERE d.user_id = u.id AND d.trust = 'trusted') AS devices,
        (SELECT MAX(seen) FROM sessions x WHERE x.user_id = u.id) AS seen
       FROM users u WHERE u.status <> 'pending' ORDER BY u.username`,
    )
    return { events, users }
  })

  route('GET', '/api/admin/analytics', { access: 'trusted', permission: 'analytics:read' }, async () => analytics.report())

  async function targetUser(s: Session, userId: string) {
    if (userId === s.userId) fail(400, 'You cannot perform this action on your own account.')
    const user = await one(`SELECT id, role, status FROM users WHERE id = $1 AND status <> 'pending'`, [userId])
    if (!user) fail(404, 'Account not found.')
    return user!
  }

  route('POST', '/api/admin/users/:id/revoke', { access: 'trusted', permission: 'account:manage', stepUp: true }, async ({ s, params }) => {
    await targetUser(s, params.id)
    await db.query(`UPDATE users SET status = 'revoked' WHERE id = $1`, [params.id])
    await db.query(`DELETE FROM envelopes WHERE recipient IN (SELECT id FROM devices WHERE user_id = $1)`, [params.id])
    await audit(s.userId, 'account.revoked', 'high', { target: params.id })
    await revokeSessions('user_id', params.id)
    return { ok: true }
  })

  route('POST', '/api/admin/users/:id/restore', { access: 'trusted', permission: 'account:manage', stepUp: true }, async ({ s, params }) => {
    const user = await targetUser(s, params.id)
    if (user.status !== 'revoked') fail(409, 'Account is not revoked.')
    await db.query(`UPDATE users SET status = 'active' WHERE id = $1`, [params.id])
    await audit(s.userId, 'account.restored', 'warning', { target: params.id })
    return { ok: true }
  })

  // Recovery path for someone who lost every trusted device: their next sign-in enrols a fresh first device.
  route('POST', '/api/admin/users/:id/reset-devices', { access: 'trusted', permission: 'account:manage', stepUp: true }, async ({ s, params }) => {
    await targetUser(s, params.id)
    const devices = await db.query<{ id: string }>(`SELECT id FROM devices WHERE user_id = $1 AND trust <> 'revoked'`, [params.id])
    for (const device of devices) await revokeDevice(s, device.id, 'device.reset_by_admin')
    return { revoked: devices.length }
  })

  route<{ role: Role }>(
    'POST',
    '/api/admin/users/:id/role',
    { access: 'trusted', permission: 'role:assign', stepUp: true, body: z.strictObject({ role: z.enum(['member', 'auditor', 'admin']) }) },
    async ({ s, body, params }) => {
      await targetUser(s, params.id)
      await db.query(`UPDATE users SET role = $1 WHERE id = $2`, [body.role, params.id])
      await audit(s.userId, 'role.changed', 'high', { target: params.id, role: body.role })
      toUser(params.id, { t: 'sync', what: 'me' })
      return { ok: true }
    },
  )

  // ---------- HTTP entry ----------

  async function readBody(request: Request, limit: number) {
    const declared = Number(request.headers.get('content-length') ?? 0)
    if (declared > limit) fail(413, 'Request is too large.')
    if (!request.body) return new Uint8Array()
    const chunks: Array<Uint8Array> = []
    let size = 0
    const reader = request.body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.length
      if (size > limit) {
        await reader.cancel()
        fail(413, 'Request is too large.')
      }
      chunks.push(value)
    }
    const out = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }
    return out
  }

  async function sweep(force = false) {
    const now = Date.now()
    if (!force && now - lastSweep < 30_000) return
    lastSweep = now
    await db.query(`DELETE FROM envelopes WHERE expires < $1`, [now])
    await db.query(`DELETE FROM attachments WHERE expires < $1`, [now])
    await db.query(`DELETE FROM replays WHERE expires < $1`, [now])
    await db.query(`DELETE FROM challenges WHERE expires < $1`, [now])
    await db.query(`DELETE FROM sessions WHERE expires < $1`, [now - 24 * HOUR])
    await db.query(`DELETE FROM audit WHERE created < $1`, [now - 30 * 24 * HOUR])
    await db.query(`DELETE FROM users WHERE status = 'pending' AND created < $1`, [now - HOUR])
    for (const [name, entry] of limits) if (entry.until < now) limits.delete(name)
    await revalidate()
  }

  async function handle(request: Request, env: { ip: string }): Promise<Response> {
    const started = performance.now()
    const url = new URL(request.url)
    const headers = new Headers({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' })
    let pattern = 'unmatched'
    let status = 200
    let response: Response
    try {
      const match = routes.map((r) => ({ r, m: r.method === request.method ? url.pathname.match(r.regex) : null })).find((x) => x.m)
      if (!match) fail(404, 'Not found.')
      const { r, m } = match!
      pattern = r.pattern
      const safe = request.method === 'GET'
      // Cookies are SameSite=Strict; the Origin check and CSRF token are defence in depth.
      if (!safe && request.headers.get('origin') !== origin) fail(403, 'Origin check failed.', 'bad-origin')
      const agent = request.headers.get('user-agent') ?? ''
      let s: Session | undefined
      if (r.policy.access !== 'public') {
        s = await authenticate({ cookie: request.headers.get('cookie'), ip: env.ip, agent })
        if (!safe && request.headers.get('x-csrf-token') !== s.csrf) fail(403, 'CSRF check failed.', 'bad-csrf')
        rate(`session:${s.hash}`, 600, MINUTE)
        authorize(s, r.policy)
      }
      if (r.policy.rate) rate(`${r.pattern}:${s?.hash ?? env.ip}`, ...r.policy.rate)
      let body: unknown
      if (r.policy.binary) body = await readBody(request, MAX_ATTACHMENT + 64)
      else if (r.policy.body) {
        let json: unknown
        try {
          json = JSON.parse(new TextDecoder().decode(await readBody(request, MAX_JSON)))
        } catch (error) {
          if (error instanceof HttpError) throw error
          fail(400, 'Invalid JSON.')
        }
        const parsed = r.policy.body.safeParse(json)
        if (!parsed.success) fail(400, 'Invalid input.', 'invalid-input')
        body = parsed.data
      }
      const params = Object.fromEntries(r.keys.map((name, i) => [name, m![i + 1]]))
      const result = await r.run({ s: s!, body, params, query: url.searchParams, ip: env.ip, agent, headers })
      if (result instanceof Response) {
        for (const [name, value] of headers) result.headers.append(name, value)
        response = result
      } else {
        headers.set('Content-Type', 'application/json')
        response = new Response(JSON.stringify(result), { headers })
      }
    } catch (error) {
      const known = error instanceof HttpError
      status = known ? error.status : 500
      headers.set('Content-Type', 'application/json')
      // Request bodies, headers, cookies and key material are never written to logs.
      if (!known) log(JSON.stringify({ event: 'error', route: pattern, name: (error as Error)?.name, code: (error as any)?.code }))
      response = new Response(JSON.stringify({ error: known ? error.message : 'Request could not be completed.', code: known ? error.code : undefined }), {
        status,
        headers,
      })
    }
    log(JSON.stringify({ event: 'request', method: request.method, route: pattern, status, ms: Math.round(performance.now() - started) }))
    background(sweep())
    return response
  }

  // ---------- realtime entry ----------

  const frameSchema = z.discriminatedUnion('t', [
    z.strictObject({ t: z.literal('ping') }),
    z.strictObject({ t: z.literal('send'), ref: z.string().max(64), message: messageSchema }),
    z.strictObject({ t: z.literal('ack'), ids: z.array(id).max(500) }),
  ])

  const realtime = {
    /** Authenticates a socket upgrade with the same checks as an HTTP request. */
    async connect(input: { cookie: string | null; origin: string | null; ip: string; agent: string }, transport: Pick<Connection, 'send' | 'close'>) {
      if (input.origin !== origin) fail(403, 'Origin denied.')
      const s = await authenticate(input)
      rate(`ws:${s.hash}`, 30, MINUTE)
      if ([...connections].filter((c) => c.hash === s.hash).length >= 4) fail(429, 'Too many connections.')
      const conn: Connection = { hash: s.hash, userId: s.userId, deviceId: s.deviceId, ...transport }
      connections.add(conn)
      const context = { cookie: input.cookie, ip: input.ip, agent: input.agent }
      return {
        conn,
        close: () => void connections.delete(conn),
        async message(raw: string) {
          let ref: string | undefined
          try {
            const parsed = frameSchema.safeParse(JSON.parse(raw))
            if (!parsed.success) return conn.send(JSON.stringify({ t: 'error', error: 'Invalid frame.' }))
            const frame = parsed.data
            if (frame.t === 'send') ref = frame.ref
            // Every frame re-authenticates: trust, role and revocation are evaluated now, not at connect time.
            const session = await authenticate(context)
            rate(`session:${session.hash}`, 600, MINUTE)
            if (frame.t === 'ping') return conn.send(JSON.stringify({ t: 'pong' }))
            authorize(session, { access: 'trusted' })
            if (frame.t === 'ack') return void (await acknowledge(session, frame.ids))
            const result = await sendMessage(session, frame.message)
            conn.send(JSON.stringify({ t: 'sent', ref, ok: true, ...result }))
          } catch (error) {
            if (error instanceof HttpError && error.status === 401) return conn.close(4001, 'Session revoked')
            const known = error instanceof HttpError
            if (!known) log(JSON.stringify({ event: 'error', route: 'ws', name: (error as Error)?.name }))
            conn.send(JSON.stringify({ t: 'sent', ref, ok: false, status: known ? error.status : 500, code: known ? error.code : undefined, error: known ? error.message : 'Request could not be completed.' }))
          }
        },
      }
    },
    get size() {
      return connections.size
    },
  }

  return { handle, realtime, sweep, analytics, db, routes: routes.map((r) => ({ method: r.method, pattern: r.pattern, policy: r.policy })) }
}
export type App = ReturnType<typeof createApp>
