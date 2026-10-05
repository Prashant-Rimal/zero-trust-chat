/**
 * Zero Trust device/session model, RBAC, revocation and the realtime channel.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ROLE_PERMISSIONS } from '~/server/app'
import * as P from '~/shared/protocol'
import { TestClient, approve, createWorld, secondDevice, settle, signUp, tick, useClock } from './harness'
import type { World } from './harness'

let world: World
let admin: TestClient
beforeAll(async () => {
  useClock()
  world = await createWorld()
  admin = await signUp(world, 'zt_admin')
})
afterAll(() => world.close())

const code = async (promise: Promise<Response>) => {
  const response = await promise
  return response.ok ? 'ok' : ((await response.json()).code ?? String(response.status))
}

describe('least privilege by default', () => {
  it('every route outside sign-in requires an authenticated session, and sensitive ones require step-up', () => {
    const open = world.app.routes.filter((r) => r.policy.access === 'public').map((r) => r.pattern)
    expect(open.sort()).toEqual(['/api/auth/login', '/api/auth/register', '/api/auth/verify'])
    const sensitive = world.app.routes.filter((r) => /approve|revoke|restore|reset-devices|role|roster/.test(r.pattern))
    expect(sensitive.length).toBeGreaterThanOrEqual(7)
    for (const route of sensitive) expect(route.policy.stepUp, route.pattern).toBe(true)
    for (const route of world.app.routes.filter((r) => r.pattern.startsWith('/api/admin/'))) expect(route.policy.permission, route.pattern).toBeTruthy()
  })

  it('unauthenticated requests are refused everywhere else', async () => {
    const anonymous = new TestClient(world, 'nobody')
    for (const route of world.app.routes.filter((r) => r.policy.access !== 'public')) {
      const path = route.pattern.replace(/:\w+/g, P.uuid())
      expect(await code(anonymous.raw(route.method, path, route.method === 'GET' ? undefined : {})), route.pattern).toBe('unauthenticated')
    }
  })

  it('the first enrolled account bootstraps as administrator; later accounts are members', async () => {
    const member = await signUp(world, 'zt_first_member')
    expect(admin.me.user.role).toBe('admin')
    expect(member.me.user.role).toBe('member')
    expect(member.me.permissions).toEqual([])
  })
})

describe('device trust', () => {
  let user: TestClient
  let peer: TestClient
  let fresh: TestClient
  let conv: string
  beforeAll(async () => {
    user = await signUp(world, 'zt_user')
    peer = await signUp(world, 'zt_peer')
    conv = await user.messenger.createConversation('direct', [peer.me.user.id])
    await peer.messenger.refresh()
  })

  it('a new device signed in with password and TOTP starts as pending and can do almost nothing', async () => {
    fresh = await secondDevice(user)
    expect(fresh.me.device.trust).toBe('pending')
    for (const [method, path] of [['GET', '/api/conversations'], ['GET', '/api/messages'], ['GET', '/api/users?q=zt_'], ['GET', '/api/prekeys'], ['GET', `/api/conversations/${conv}/directory`]])
      expect(await code(fresh.raw(method, path))).toBe('device-pending')
    expect(await code(fresh.raw('GET', '/api/me'))).toBe('ok')
    expect(await code(fresh.raw('GET', '/api/devices'))).toBe('ok')
    await expect(world.app.realtime.connect({ cookie: fresh.cookie, origin: fresh.origin, ip: fresh.ip, agent: fresh.agent }, { send() {}, close() {} })).resolves.toBeTruthy()
  })

  it('a pending device is invisible to contacts and receives no ciphertext', async () => {
    tick(20_000)
    await peer.messenger.send(conv, 'not for the pending device')
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [fresh.vault.keys.deviceId])).toHaveLength(0)
    const directory = await peer.api('GET', `/api/conversations/${conv}/directory`)
    expect(directory.devices.some((d: any) => d.id === fresh.vault.keys.deviceId)).toBe(false)
    await user.sync()
  })

  it('a pending device cannot approve itself, and approval needs step-up plus a valid cross-signature', async () => {
    const selfSig = P.crossSign(fresh.vault.keys, user.me.user.id, fresh.vault.keys.deviceId, fresh.vault.keys.ik.pub)
    expect(await code(fresh.raw('POST', `/api/devices/${fresh.vault.keys.deviceId}/approve`, { sig: selfSig }))).toBe('device-pending')
    tick(6 * 60_000)
    expect(await code(user.raw('POST', `/api/devices/${fresh.vault.keys.deviceId}/approve`, { sig: selfSig }))).toBe('step-up-required')
    await user.stepUp()
    expect(await code(user.raw('POST', `/api/devices/${fresh.vault.keys.deviceId}/approve`, { sig: selfSig }))).toBe('bad-signature')
    // Another account cannot approve it either.
    await peer.stepUp()
    const peerSig = P.crossSign(peer.vault.keys, user.me.user.id, fresh.vault.keys.deviceId, fresh.vault.keys.ik.pub)
    expect(await code(peer.raw('POST', `/api/devices/${fresh.vault.keys.deviceId}/approve`, { sig: peerSig }))).toBe('404')
  })

  it('once a trusted device vouches for it, the new device becomes trusted and starts receiving', async () => {
    await approve(user, fresh)
    expect(fresh.me.device.trust).toBe('trusted')
    tick(20_000)
    await peer.messenger.send(conv, 'to both devices')
    await user.sync()
    await fresh.sync()
    expect(user.texts(conv)).toContain('to both devices')
    expect(fresh.texts(conv)).toEqual(['to both devices'])
    // Messages sent from one device reach the account's other device too.
    await fresh.messenger.send(conv, 'sent from my new device')
    await user.sync()
    await peer.sync()
    expect(user.messenger.messages(conv).at(-1)).toMatchObject({ text: 'sent from my new device', mine: true })
    expect(peer.texts(conv).at(-1)).toBe('sent from my new device')
    const events = (await user.api('GET', '/api/security')).events.map((e: any) => e.kind)
    expect(events).toEqual(expect.arrayContaining(['device.enrolled', 'device.approved']))
  })

  it('revoking a device ends its sessions immediately and excludes it from future messages', async () => {
    const socket = await fresh.connect()
    await user.stepUp()
    await user.api('POST', `/api/devices/${fresh.vault.keys.deviceId}/revoke`)
    await settle()
    expect(socket.closed).toEqual({ code: 4001, reason: 'Session revoked' })
    expect(await code(fresh.raw('GET', '/api/me'))).toBe('unauthenticated')
    tick(20_000)
    await peer.messenger.send(conv, 'after revocation')
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [fresh.vault.keys.deviceId])).toHaveLength(0)
    // The revoked identity can never sign in again, even with valid password and TOTP.
    const { challenge } = await fresh.api('POST', '/api/auth/login', { username: user.username, authKey: user.authKey })
    await expect(fresh.verify(challenge)).rejects.toMatchObject({ code: 'device-rejected' })
    await user.sync()
  })
})

describe('continuous verification', () => {
  it('sessions expire when idle and after their absolute lifetime', async () => {
    const idle = await signUp(world, 'zt_idle')
    tick(31 * 60_000)
    expect(await code(idle.raw('GET', '/api/me'))).toBe('unauthenticated')
    const long = await signUp(world, 'zt_long')
    for (let i = 0; i < 16; i++) {
      tick(29 * 60_000)
      expect(await code(long.raw('GET', '/api/me'))).toBe('ok')
    }
    tick(20 * 60_000)
    expect(await code(long.raw('GET', '/api/me'))).toBe('unauthenticated')
  })

  it('step-up freshness lapses after five minutes', async () => {
    const user = await signUp(world, 'zt_stepup')
    const other = await secondDevice(user)
    await user.stepUp()
    tick(5 * 60_000 + 1000)
    expect(await code(user.raw('POST', `/api/devices/${other.vault.keys.deviceId}/revoke`, {}))).toBe('step-up-required')
    await user.stepUp()
    expect(await code(user.raw('POST', `/api/devices/${other.vault.keys.deviceId}/revoke`, {}))).toBe('ok')
  })

  it('a session that moves to a new network loses step-up freshness and is flagged', async () => {
    const user = await signUp(world, 'zt_roam')
    const other = await secondDevice(user)
    await user.stepUp()
    user.ip = '203.0.113.50'
    expect(await code(user.raw('GET', '/api/me'))).toBe('ok')
    expect(await code(user.raw('POST', `/api/devices/${other.vault.keys.deviceId}/revoke`, {}))).toBe('step-up-required')
    const events = (await user.api('GET', '/api/security')).events
    expect(events.some((e: any) => e.kind === 'session.context_changed' && e.severity === 'warning')).toBe(true)
    // Re-verifying resets the session's risk.
    await user.stepUp()
    expect(await code(user.raw('POST', `/api/devices/${other.vault.keys.deviceId}/revoke`, {}))).toBe('ok')
  })

  it('a session cookie replayed from a different browser and network is revoked', async () => {
    const victim = await signUp(world, 'zt_victim')
    const thief = new TestClient(world, 'thief')
    thief.cookie = victim.cookie
    thief.csrf = victim.csrf
    thief.agent = 'curl/8.0'
    thief.ip = '198.51.100.9'
    expect(await code(thief.raw('GET', '/api/conversations'))).toBe('unauthenticated')
    // The legitimate browser is signed out too: the token is burnt, and the owner is told why.
    expect(await code(victim.raw('GET', '/api/me'))).toBe('unauthenticated')
    await victim.login()
    const events = (await victim.api('GET', '/api/security')).events
    expect(events.some((e: any) => e.kind === 'session.risk_revoked' && e.severity === 'high')).toBe(true)
  })

  it('signing in from an unfamiliar network is surfaced as a login anomaly', async () => {
    const user = await signUp(world, 'zt_travel')
    await user.api('POST', '/api/auth/logout', {})
    user.ip = '192.0.2.77'
    await user.login()
    expect((await user.api('GET', '/api/security')).events.some((e: any) => e.kind === 'login.new_network')).toBe(true)
  })
})

describe('session revocation and realtime delivery', () => {
  let a: TestClient
  let b: TestClient
  let conv: string
  beforeAll(async () => {
    a = await signUp(world, 'rt_alice')
    b = await signUp(world, 'rt_bob')
    conv = await a.messenger.createConversation('direct', [b.me.user.id])
    await b.sync()
  })

  it('pushes ciphertext to connected recipient devices and accepts sends over the socket', async () => {
    const socket = await b.connect()
    await a.messenger.send(conv, 'pushed live')
    await settle()
    const pushed = socket.frames.filter((f) => f.t === 'envelope')
    expect(pushed).toHaveLength(1)
    await b.messenger.receive(pushed.map((f) => f.e))
    expect(b.texts(conv)).toEqual(['pushed live'])

    // Send through the socket: capture what the client would post and submit it as a frame instead.
    const aSocket = await a.connect()
    let captured: unknown
    const original = b.transport.send
    b.transport.send = async (message: any) => {
      if (message.t === 'ack') return null
      captured = message
      await socket.message(JSON.stringify({ t: 'send', ref: 'r1', message }))
      return socket.frames.find((f) => f.t === 'sent' && f.ref === 'r1')
    }
    await b.messenger.send(conv, 'sent over websocket')
    b.transport.send = original
    expect(captured).toBeTruthy()
    expect(socket.frames.find((f) => f.t === 'sent')).toMatchObject({ ok: true, delivered: 1 })
    await settle()
    await a.messenger.receive(aSocket.frames.filter((f) => f.t === 'envelope').map((f) => f.e))
    expect(a.texts(conv)).toEqual(['pushed live', 'sent over websocket'])
    socket.close()
    aSocket.close()
  })

  it('ends a revoked session on the next request and closes its socket', async () => {
    const second = await secondDevice(a)
    await approve(a, second)
    const socket = await second.connect()
    const sessions = (await a.api('GET', '/api/devices')).sessions
    const target = sessions.find((s: any) => s.device_id === second.vault.keys.deviceId && s.active)
    await a.stepUp()
    await a.api('POST', `/api/sessions/${target.id}/revoke`)
    await settle()
    expect(socket.closed?.code).toBe(4001)
    expect(await code(second.raw('GET', '/api/messages'))).toBe('unauthenticated')
    // The device itself stays trusted: it can sign in again with all three factors.
    await second.login()
    expect(second.me.device.trust).toBe('trusted')
  })

  it('a socket frame from a session revoked after connecting is refused and the socket closed', async () => {
    const socket = await b.connect()
    await world.db.query(`UPDATE sessions SET revoked = TRUE WHERE user_id = $1`, [b.me.user.id])
    await socket.message(JSON.stringify({ t: 'send', ref: 'x', message: { id: P.uuid(), conv, created: Date.now(), expires: Date.now() + 60_000, envelopes: [{ to: a.vault.keys.deviceId, header: { dh: b.vault.keys.dh.pub, pn: 0, n: 0 }, pre: null, nonce: P.b64(new Uint8Array(24)), ct: P.b64(new Uint8Array(272)) }] } }))
    expect(socket.closed?.code).toBe(4001)
    expect(socket.frames.some((f) => f.t === 'sent')).toBe(false)
    await b.login()
  })

  it('no envelope is pushed to a socket whose session was revoked moments earlier', async () => {
    const socket = await b.connect()
    await world.db.query(`UPDATE sessions SET revoked = TRUE WHERE user_id = $1`, [b.me.user.id])
    await a.messenger.send(conv, 'must not reach the dead session')
    await settle()
    expect(socket.frames.filter((f) => f.t === 'envelope')).toHaveLength(0)
    expect(socket.closed?.code).toBe(4001)
    await b.login()
  })

  it('signing out invalidates the token server-side', async () => {
    const user = await signUp(world, 'rt_logout')
    const cookie = user.cookie
    await user.api('POST', '/api/auth/logout', {})
    user.cookie = cookie
    expect(await code(user.raw('GET', '/api/me'))).toBe('unauthenticated')
  })
})

describe('role-based access control', () => {
  let member: TestClient
  let auditor: TestClient
  let target: TestClient
  beforeAll(async () => {
    member = await signUp(world, 'rb_member')
    auditor = await signUp(world, 'rb_auditor')
    target = await signUp(world, 'rb_target')
    await admin.login()
    await admin.stepUp()
    await admin.api('POST', `/api/admin/users/${auditor.me.user.id}/role`, { role: 'auditor' })
  })

  it('declares permissions per role', () => {
    expect(ROLE_PERMISSIONS.member).toEqual([])
    expect(ROLE_PERMISSIONS.auditor).toEqual(['audit:read', 'analytics:read'])
    expect(ROLE_PERMISSIONS.admin).toEqual(expect.arrayContaining(['account:manage', 'role:assign']))
  })

  it('members cannot reach any administrative function, even with a fresh second factor', async () => {
    await member.stepUp()
    for (const [method, path, body] of [
      ['GET', '/api/admin/overview'], ['GET', '/api/admin/analytics'],
      ['POST', `/api/admin/users/${target.me.user.id}/revoke`, {}], ['POST', `/api/admin/users/${target.me.user.id}/restore`, {}],
      ['POST', `/api/admin/users/${target.me.user.id}/reset-devices`, {}], ['POST', `/api/admin/users/${member.me.user.id}/role`, { role: 'admin' }],
    ] as const)
      expect(await code(member.raw(method, path, body)), path).toBe('forbidden')
  })

  it('auditors can read the workspace audit trail and analytics but cannot act on accounts', async () => {
    const overview = await auditor.api('GET', '/api/admin/overview')
    expect(overview.users.length).toBeGreaterThan(3)
    expect(overview.events.length).toBeGreaterThan(0)
    await auditor.api('GET', '/api/admin/analytics')
    await auditor.stepUp()
    expect(await code(auditor.raw('POST', `/api/admin/users/${target.me.user.id}/revoke`, {}))).toBe('forbidden')
    expect(await code(auditor.raw('POST', `/api/admin/users/${auditor.me.user.id}/role`, { role: 'admin' }))).toBe('forbidden')
  })

  it('administrators need step-up, cannot act on themselves, and a role change takes effect at once', async () => {
    tick(6 * 60_000)
    expect(await code(admin.raw('POST', `/api/admin/users/${target.me.user.id}/revoke`, {}))).toBe('step-up-required')
    await admin.stepUp()
    expect(await code(admin.raw('POST', `/api/admin/users/${admin.me.user.id}/revoke`, {}))).toBe('400')
    expect(await code(admin.raw('POST', `/api/admin/users/${admin.me.user.id}/role`, { role: 'member' }))).toBe('400')
    await admin.api('POST', `/api/admin/users/${auditor.me.user.id}/role`, { role: 'member' })
    expect(await code(auditor.raw('GET', '/api/admin/overview'))).toBe('forbidden')
  })

  it('revoking an account cuts off every session and socket, blocks sign-in, and can be restored', async () => {
    const socket = await target.connect()
    await admin.stepUp()
    await admin.api('POST', `/api/admin/users/${target.me.user.id}/revoke`)
    await settle()
    expect(socket.closed?.code).toBe(4001)
    expect(await code(target.raw('GET', '/api/me'))).toBe('unauthenticated')
    expect(await code(target.raw('POST', '/api/auth/login', { username: target.username, authKey: target.authKey }))).toBe('bad-credentials')
    expect((await admin.api('GET', '/api/admin/overview')).events.some((e: any) => e.kind === 'account.revoked' && e.severity === 'high')).toBe(true)
    await admin.api('POST', `/api/admin/users/${target.me.user.id}/restore`)
    await target.login()
    expect(await code(target.raw('GET', '/api/me'))).toBe('ok')
  })

  it('an administrator can reset device trust for someone who lost every device', async () => {
    await admin.stepUp()
    const result = await admin.api('POST', `/api/admin/users/${target.me.user.id}/reset-devices`)
    expect(result.revoked).toBe(1)
    const replacement = await secondDevice(target)
    expect(replacement.me.device.trust).toBe('trusted')
  })

  it('administrators have no route to message content', () => {
    const adminRoutes = world.app.routes.filter((r) => r.policy.permission).map((r) => r.pattern)
    expect(adminRoutes.every((p) => p.startsWith('/api/admin/'))).toBe(true)
    expect(adminRoutes.some((p) => /message|envelope|attachment|conversation/.test(p))).toBe(false)
  })
})
