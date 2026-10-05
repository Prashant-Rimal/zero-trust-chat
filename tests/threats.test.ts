/**
 * Threat-model-based tests: impersonation, key substitution, unauthorised group access and
 * metadata leakage. Where the adversary is the relay itself, the test edits the database directly.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { Messenger } from '~/client/messenger'
import { totp } from '~/server/crypto'
import * as P from '~/shared/protocol'
import { ORIGIN, TestClient, approve, createWorld, dump, secondDevice, signUp, tick, useClock } from './harness'
import type { World } from './harness'

let world: World
beforeAll(async () => {
  useClock()
  world = await createWorld()
})
afterAll(() => world.close())

const status = async (promise: Promise<Response>) => (await promise).status

describe('impersonation', () => {
  let alice: TestClient
  let mallory: TestClient
  beforeAll(async () => {
    alice = await signUp(world, 'imp_alice')
    mallory = await signUp(world, 'imp_mallory')
  })

  it('a password alone is not enough: no session exists until the TOTP step succeeds', async () => {
    const thief = new TestClient(world, alice.username)
    const { challenge } = await thief.api('POST', '/api/auth/login', { username: alice.username, authKey: alice.authKey })
    expect(challenge).toBeTypeOf('string')
    expect(thief.cookie).toBe('')
    expect(await status(thief.raw('GET', '/api/me'))).toBe(401)
    const wrong = await thief.raw('POST', '/api/auth/verify', Messenger.enrolment(thief.vault, challenge, '000000', 'thief'))
    expect(wrong.status).toBe(401)
    expect(thief.cookie).toBe('')
  })

  it('rejects a wrong password without revealing whether the account exists', async () => {
    const wrong = await alice.raw('POST', '/api/auth/login', { username: alice.username, authKey: mallory.authKey })
    const missing = await alice.raw('POST', '/api/auth/login', { username: 'no_such_user', authKey: mallory.authKey })
    expect(wrong.status).toBe(401)
    expect(await wrong.json()).toEqual(await missing.json())
  })

  it('a TOTP code cannot be used twice', async () => {
    const thief = new TestClient(world, alice.username)
    tick(30_000)
    const code = totp(alice.totpSecret)
    await alice.api('POST', '/api/auth/stepup', { code })
    const { challenge } = await thief.api('POST', '/api/auth/login', { username: alice.username, authKey: alice.authKey })
    const response = await thief.raw('POST', '/api/auth/verify', Messenger.enrolment(thief.vault, challenge, code, 'thief'))
    expect(response.status).toBe(401)
    expect((await response.json()).code).toBe('bad-code')
  })

  it('a device id cannot be claimed without its identity key', async () => {
    const thief = new TestClient(world, alice.username)
    thief.totpSecret = alice.totpSecret
    // Same device id as Alice's real device, different keys.
    thief.vault = { ...thief.vault, keys: P.generateDeviceKeys(alice.vault.keys.deviceId) }
    const { challenge } = await thief.api('POST', '/api/auth/login', { username: alice.username, authKey: alice.authKey })
    const response = await thief.raw('POST', '/api/auth/verify', Messenger.enrolment(thief.vault, challenge, thief.code(), 'clone'))
    expect(response.status).toBe(403)
    expect((await response.json()).code).toBe('device-rejected')
    const events = (await alice.api('GET', '/api/security')).events
    expect(events.some((e: any) => e.kind === 'device.identity_mismatch' && e.severity === 'high')).toBe(true)
  })

  it('a login proof signed by a different key is rejected', async () => {
    const thief = new TestClient(world, alice.username)
    thief.totpSecret = alice.totpSecret
    const { challenge } = await thief.api('POST', '/api/auth/login', { username: alice.username, authKey: alice.authKey })
    const body = Messenger.enrolment(thief.vault, challenge, thief.code(), 'x')
    body.proof = P.signLogin(P.generateDeviceKeys(thief.vault.keys.deviceId), challenge)
    const response = await thief.raw('POST', '/api/auth/verify', body)
    expect((await response.json()).code).toBe('bad-proof')
  })

  it('the sender device is taken from the session, never from the request', async () => {
    const conv = await alice.messenger.createConversation('direct', [mallory.me.user.id])
    await mallory.sync()
    const forged = { id: P.uuid(), conv, created: Date.now(), expires: Date.now() + 60_000, from: alice.vault.keys.deviceId, envelopes: [] }
    expect(await status(mallory.raw('POST', '/api/messages', forged))).toBe(400)
  })

  it('a stolen session cookie is useless without the CSRF token and matching origin', async () => {
    const stolen = new TestClient(world, 'x')
    stolen.cookie = alice.cookie
    stolen.agent = alice.agent
    stolen.ip = alice.ip
    const noCsrf = await stolen.raw('POST', '/api/auth/logout', {})
    expect((await noCsrf.json()).code).toBe('bad-csrf')
    stolen.csrf = alice.csrf
    stolen.origin = 'https://evil.example'
    const crossSite = await stolen.raw('POST', '/api/auth/logout', {})
    expect((await crossSite.json()).code).toBe('bad-origin')
    await expect(world.app.realtime.connect({ cookie: alice.cookie, origin: 'https://evil.example', ip: alice.ip, agent: alice.agent }, { send() {}, close() {} })).rejects.toThrow(/Origin/)
  })

  it('repeated failed sign-ins raise a brute-force signal on the dashboard', async () => {
    const victim = await signUp(world, 'imp_victim')
    for (let i = 0; i < 5; i++) await mallory.raw('POST', '/api/auth/login', { username: victim.username, authKey: mallory.authKey })
    const events = (await victim.api('GET', '/api/security')).events
    expect(events.filter((e: any) => e.kind === 'login.failed')).toHaveLength(5)
    expect(events.filter((e: any) => e.kind === 'login.bruteforce_suspected')).toHaveLength(1)
  })

  it('throttles guessing', async () => {
    const attacker = new TestClient(world, 'imp_alice')
    let last = 0
    for (let i = 0; i < 12; i++) last = await status(attacker.raw('POST', '/api/auth/login', { username: 'throttle_target', authKey: attacker.authKey }))
    expect(last).toBe(429)
  })
})

describe('key substitution by a malicious relay', () => {
  let alice: TestClient
  let bob: TestClient
  let conv: string
  beforeAll(async () => {
    alice = await signUp(world, 'ks_alice')
    bob = await signUp(world, 'ks_bob')
    conv = await alice.messenger.createConversation('direct', [bob.me.user.id])
    await alice.messenger.send(conv, 'before the attack')
    await bob.sync()
  })

  it('swapping a pinned identity key blocks sending instead of silently re-keying', async () => {
    const attacker = P.generateDeviceKeys(bob.vault.keys.deviceId)
    const original = await world.db.query(`SELECT ik, dh, dh_sig, spk_id, spk, spk_sig FROM devices WHERE id = $1`, [attacker.deviceId])
    await world.db.query(`UPDATE devices SET ik = $1, dh = $2, dh_sig = $3, spk = $4, spk_sig = $5 WHERE id = $6`, [attacker.ik.pub, attacker.dh.pub, attacker.dhSig, attacker.spk.pub, attacker.spk.sig, attacker.deviceId])
    tick(20_000)
    await expect(alice.messenger.send(conv, 'for bob only')).rejects.toThrow(/identity key .* changed/)
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [attacker.deviceId])).toHaveLength(0)
    const o = original[0]
    await world.db.query(`UPDATE devices SET ik = $1, dh = $2, dh_sig = $3, spk = $4, spk_sig = $5 WHERE id = $6`, [o.ik, o.dh, o.dh_sig, o.spk, o.spk_sig, attacker.deviceId])
    tick(20_000)
  })

  it('swapping only the signed prekey fails the signature check during session setup', async () => {
    const carol = await signUp(world, 'ks_carol')
    const withCarol = await alice.messenger.createConversation('direct', [carol.me.user.id])
    const attacker = P.generateDeviceKeys(carol.vault.keys.deviceId)
    await world.db.query(`UPDATE devices SET spk = $1, spk_sig = $2 WHERE id = $3`, [attacker.spk.pub, attacker.spk.sig, attacker.deviceId])
    await expect(alice.messenger.send(withCarol, 'hi carol')).rejects.toThrow(/signed prekey/)
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE conv = $1`, [withCarol])).toHaveLength(0)
  })

  it('the relay cannot register a prekey that the device identity did not sign', async () => {
    const attacker = P.generateDeviceKeys(bob.vault.keys.deviceId)
    const response = await bob.raw('POST', '/api/prekeys', { spk: { id: 99, pub: attacker.spk.pub, sig: attacker.spk.sig }, opks: [] })
    expect((await response.json()).code).toBe('bad-signature')
  })

  it('a ghost device injected under a contact clears their verified status and raises a warning', async () => {
    await alice.messenger.verify(bob.me.user.id, bob.messenger.verificationCode())
    expect(alice.messenger.isVerified(bob.me.user.id)).toBe(true)
    const ghost = P.generateDeviceKeys()
    await world.db.query(
      `INSERT INTO devices(id, user_id, label, ik, dh, dh_sig, spk_id, spk, spk_sig, spk_at, trust, created, seen) VALUES ($1,$2,'ghost',$3,$4,$5,1,$6,$7,0,'trusted',0,0)`,
      [ghost.deviceId, bob.me.user.id, ghost.ik.pub, ghost.dh.pub, ghost.dhSig, ghost.spk.pub, ghost.spk.sig],
    )
    tick(20_000)
    await alice.messenger.refresh()
    expect(alice.messenger.isVerified(bob.me.user.id)).toBe(false)
    expect(alice.messenger.notices(conv).at(-1)).toMatchObject({ kind: 'warning' })
    expect(alice.messenger.notices(conv).at(-1)!.text).toMatch(/no known device vouched/)
    // The security code Alice now computes no longer matches what Bob's real device shows.
    expect(alice.messenger.verificationCode(bob.me.user.id)).not.toBe(bob.messenger.verificationCode())
    await expect(alice.messenger.verify(bob.me.user.id, bob.messenger.verificationCode())).rejects.toThrow(/does not match/)
    await world.db.query(`DELETE FROM devices WHERE id = $1`, [ghost.deviceId])
  })

  it('a device the account owner cross-signed is accepted without downgrading verification', async () => {
    const dave = await signUp(world, 'ks_dave')
    const erin = await signUp(world, 'ks_erin')
    const c = await dave.messenger.createConversation('direct', [erin.me.user.id])
    await erin.sync()
    await dave.messenger.verify(erin.me.user.id, erin.messenger.verificationCode())
    const erin2 = await secondDevice(erin)
    await approve(erin, erin2)
    tick(20_000)
    await dave.messenger.refresh()
    expect(dave.messenger.isVerified(erin.me.user.id)).toBe(true)
    expect(dave.messenger.notices(c).at(-1)).toMatchObject({ kind: 'info' })
    await dave.messenger.send(c, 'to both of erin’s devices')
    await erin.sync()
    await erin2.sync()
    expect(erin.texts(c)).toEqual(['to both of erin’s devices'])
    expect(erin2.texts(c)).toEqual(['to both of erin’s devices'])
    // A forged cross-signature (signed by someone else's device) is not accepted as vouching.
    const ghost = P.generateDeviceKeys()
    const forged = P.crossSign(dave.vault.keys, erin.me.user.id, ghost.deviceId, ghost.ik.pub)
    await world.db.query(
      `INSERT INTO devices(id, user_id, label, ik, dh, dh_sig, spk_id, spk, spk_sig, spk_at, trust, xsig_by, xsig, created, seen) VALUES ($1,$2,'ghost',$3,$4,$5,1,$6,$7,0,'trusted',$8,$9,0,0)`,
      [ghost.deviceId, erin.me.user.id, ghost.ik.pub, ghost.dh.pub, ghost.dhSig, ghost.spk.pub, ghost.spk.sig, dave.vault.keys.deviceId, forged],
    )
    tick(20_000)
    await dave.messenger.refresh()
    expect(dave.messenger.isVerified(erin.me.user.id)).toBe(false)
  })

  it('a relay that answers a handshake with its own keys cannot read or forge messages', async () => {
    const frank = await signUp(world, 'ks_frank')
    const grace = await signUp(world, 'ks_grace')
    const c = await frank.messenger.createConversation('direct', [grace.me.user.id])
    await grace.sync()
    const sent = await frank.messenger.send(c, 'for grace')
    const [row] = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE id = $1`, [sent.id])
    const e: P.Envelope = JSON.parse(row.body)
    // The relay holds every public key and the full envelope, but none of the X3DH private inputs.
    const relay = P.generateDeviceKeys(grace.vault.keys.deviceId)
    const frankPublic = { id: frank.vault.keys.deviceId, ik: frank.vault.keys.ik.pub, dh: frank.vault.keys.dh.pub, dhSig: frank.vault.keys.dhSig }
    relay.spk = { ...relay.spk, id: e.pre!.spk }
    if (e.pre!.opk !== null) relay.opks[e.pre!.opk] = { priv: relay.dh.priv, pub: relay.dh.pub }
    expect(() => P.ratchetDecrypt(P.acceptSession(relay, frankPublic, e.pre!), e)).toThrow(P.ProtocolError)
  })
})

describe('unauthorised group access', () => {
  let owner: TestClient
  let member: TestClient
  let leaver: TestClient
  let outsider: TestClient
  let group: string
  beforeAll(async () => {
    owner = await signUp(world, 'ga_owner')
    member = await signUp(world, 'ga_member')
    leaver = await signUp(world, 'ga_leaver')
    outsider = await signUp(world, 'ga_outsider')
    group = await owner.messenger.createConversation('group', [member.me.user.id, leaver.me.user.id], 'Planning')
    for (const c of [member, leaver]) await c.sync()
  })

  it('an outsider cannot list members, fetch keys, post, upload or download', async () => {
    expect(await status(outsider.raw('GET', `/api/conversations/${group}/directory`))).toBe(403)
    expect(await status(outsider.raw('POST', `/api/devices/${member.vault.keys.deviceId}/bundle`, {}))).toBe(404)
    const message = { id: P.uuid(), conv: group, created: Date.now(), expires: Date.now() + 60_000, envelopes: [{ to: member.vault.keys.deviceId, header: { dh: outsider.vault.keys.dh.pub, pn: 0, n: 0 }, pre: null, nonce: P.b64(new Uint8Array(24)), ct: P.b64(new Uint8Array(272)) }] }
    expect(await status(outsider.raw('POST', '/api/messages', message))).toBe(403)
    expect(await status(outsider.raw('POST', `/api/conversations/${group}/attachments?expires=${Date.now() + 60_000}`, new Uint8Array(10)))).toBe(403)
    await owner.messenger.send(group, 'with file', { file: { name: 'f', type: 't', bytes: new Uint8Array(64) } })
    await member.sync()
    const file = member.messenger.messages(group).find((m) => m.file)!.file!
    expect(await status(outsider.raw('GET', `/api/attachments/${file.id}`))).toBe(403)
    expect((await outsider.api('GET', '/api/conversations')).some((c: any) => c.id === group)).toBe(false)
    expect((await outsider.api('GET', '/api/security')).events.some((e: any) => e.kind === 'access.denied')).toBe(true)
  })

  it('a member cannot address ciphertext to a device outside the conversation', async () => {
    const message = { id: P.uuid(), conv: group, created: Date.now(), expires: Date.now() + 60_000, envelopes: [{ to: outsider.vault.keys.deviceId, header: { dh: member.vault.keys.dh.pub, pn: 0, n: 0 }, pre: null, nonce: P.b64(new Uint8Array(24)), ct: P.b64(new Uint8Array(272)) }] }
    const response = await member.raw('POST', '/api/messages', message)
    expect(response.status).toBe(409)
  })

  it('only the owner can change membership, and only with a fresh second factor', async () => {
    const forged = P.signRoster(member.vault.keys, { v: 1, conv: group, epoch: 2, kind: 'group', owner: member.me.user.id, members: [member.me.user.id, outsider.me.user.id] })
    await member.stepUp()
    expect(await status(member.raw('PUT', `/api/conversations/${group}/roster`, forged))).toBe(403)
    tick(6 * 60_000)
    await expect(owner.messenger.setMembers(group, [member.me.user.id])).rejects.toMatchObject({ code: 'step-up-required' })
    // A roster the owner did not sign is rejected even with step-up.
    await owner.stepUp()
    const wrongSigner = { ...P.signRoster(member.vault.keys, { v: 1, conv: group, epoch: 2, kind: 'group', owner: owner.me.user.id, members: [owner.me.user.id, outsider.me.user.id] }), signer: owner.vault.keys.deviceId }
    expect((await (await owner.raw('PUT', `/api/conversations/${group}/roster`, wrongSigner)).json()).code).toBe('bad-signature')
  })

  it('a removed member stops receiving: no new ciphertext is produced for them and queued ciphertext is discarded', async () => {
    await owner.messenger.send(group, 'queued for leaver before removal')
    await owner.stepUp()
    await owner.messenger.setMembers(group, [member.me.user.id])
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1 AND conv = $2`, [leaver.vault.keys.deviceId, group])).toHaveLength(0)
    await member.sync()
    await member.messenger.refresh()
    await member.messenger.send(group, 'after removal')
    await owner.messenger.send(group, 'owner after removal')
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1 AND conv = $2`, [leaver.vault.keys.deviceId, group])).toHaveLength(0)
    expect(await status(leaver.raw('GET', `/api/conversations/${group}/directory`))).toBe(403)
    await leaver.sync()
    expect(leaver.texts(group)).not.toContain('after removal')
    expect(member.messenger.notices(group).some((n) => /removed ga_leaver/.test(n.text))).toBe(true)
  })

  it('a member the relay adds behind the owner’s back receives nothing: clients encrypt only to the signed roster', async () => {
    await world.db.query(`INSERT INTO members(conv, user_id) VALUES ($1, $2)`, [group, outsider.me.user.id])
    tick(20_000)
    await owner.messenger.refresh()
    await member.messenger.refresh()
    await owner.messenger.send(group, 'members only')
    await member.sync()
    await member.messenger.send(group, 'still members only')
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [outsider.vault.keys.deviceId])).toHaveLength(0)
    // The injected account can now reach the API, but a message it sends is refused by honest clients.
    await outsider.messenger.refresh()
    const injected = outsider.messenger.conversations.find((c) => c.id === group)
    expect(injected?.problem).toMatch(/Roster does not match/)
    await expect(outsider.messenger.send(group, 'let me in')).rejects.toThrow(/blocked/)
    await world.db.query(`DELETE FROM members WHERE conv = $1 AND user_id = $2`, [group, outsider.me.user.id])
  })

  it('a rolled-back or re-signed-by-someone-else roster is refused and sending is blocked', async () => {
    const [current] = await world.db.query(`SELECT epoch, roster, signer, sig FROM conversations WHERE id = $1`, [group])
    const old = P.signRoster(owner.vault.keys, { v: 1, conv: group, epoch: 1, kind: 'group', owner: owner.me.user.id, members: [owner.me.user.id, member.me.user.id, leaver.me.user.id] })
    await world.db.query(`UPDATE conversations SET epoch = 1, roster = $1::jsonb, sig = $2 WHERE id = $3`, [JSON.stringify(old.roster), old.sig, group])
    await world.db.query(`INSERT INTO members(conv, user_id) VALUES ($1, $2)`, [group, leaver.me.user.id])
    tick(20_000)
    await member.messenger.refresh()
    expect(member.messenger.conversations.find((c) => c.id === group)!.problem).toMatch(/rolled back/)
    await expect(member.messenger.send(group, 'should not go out')).rejects.toThrow(/blocked/)
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1 AND conv = $2`, [leaver.vault.keys.deviceId, group])).toHaveLength(0)
    await world.db.query(`UPDATE conversations SET epoch = $1, roster = $2::jsonb, sig = $3 WHERE id = $4`, [current.epoch, JSON.stringify(current.roster), current.sig, group])
    await world.db.query(`DELETE FROM members WHERE conv = $1 AND user_id = $2`, [group, leaver.me.user.id])
    tick(20_000)
    await member.messenger.refresh()
    expect(member.messenger.conversations.find((c) => c.id === group)!.problem).toBeUndefined()
  })

  it('usernames cannot be enumerated in bulk', async () => {
    expect(await outsider.api('GET', '/api/users?q=')).toEqual([])
    expect(await outsider.api('GET', '/api/users?q=g')).toEqual([])
    expect(await outsider.api('GET', '/api/users?q=%25')).toEqual([])
    const found = await outsider.api('GET', '/api/users?q=ga_')
    expect(found.length).toBeGreaterThan(0)
    expect(found.length).toBeLessThanOrEqual(10)
    expect(Object.keys(found[0]).sort()).toEqual(['id', 'username'])
  })
})

describe('metadata leakage', () => {
  it('documents exactly what the relay stores for a queued message, and nothing more', async () => {
    const a = await signUp(world, 'md_alice')
    const b = await signUp(world, 'md_bob')
    const group = await a.messenger.createConversation('group', [b.me.user.id], 'Secret project name')
    await a.messenger.send(group, 'hello')
    const columns = await world.db.query<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position`,
    )
    const schema: Record<string, Array<string>> = {}
    for (const c of columns) (schema[c.table_name] ??= []).push(c.column_name)
    // The conversation table has no name, topic or description column to leak.
    expect(schema.conversations).toEqual(['id', 'kind', 'owner', 'epoch', 'roster', 'signer', 'sig', 'created'])
    expect(schema.envelopes).toEqual(['id', 'recipient', 'conv', 'body', 'created', 'expires'])
    expect(schema.audit).toEqual(['id', 'user_id', 'kind', 'severity', 'detail', 'created'])
    const [row] = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE conv = $1 ORDER BY created DESC LIMIT 1`, [group])
    expect(Object.keys(JSON.parse(row.body)).sort()).toEqual(['conv', 'created', 'ct', 'expires', 'from', 'header', 'id', 'nonce', 'pre', 'to'])
    expect(await dump(world.db)).not.toContain('Secret project name')
  })

  it('keeps the sign-up email as a record that only administrators and auditors can read', async () => {
    const admin = await signUp(world, 'md_admin_view')
    await world.db.query(`UPDATE users SET role = 'admin' WHERE id = $1`, [admin.me.user.id])
    const member = await signUp(world, 'md_email_owner')
    const peer = await signUp(world, 'md_email_peer')
    const conv = await member.messenger.createConversation('direct', [peer.me.user.id])
    const [row] = await world.db.query(`SELECT email FROM users WHERE id = $1`, [member.me.user.id])
    expect(row.email).toBe('md_email_owner@example.test')
    const overview = await admin.api('GET', '/api/admin/overview')
    expect(overview.users.find((u: any) => u.id === member.me.user.id).email).toBe('md_email_owner@example.test')
    // Nothing an ordinary member can call returns anyone's address, including their own contacts'.
    const visible = JSON.stringify([
      await peer.api('GET', '/api/users?q=md_email'),
      await peer.api('GET', `/api/conversations/${conv}/directory`),
      await peer.api('GET', '/api/conversations'),
      await peer.api('GET', '/api/me'),
      await peer.api('GET', '/api/security'),
    ])
    expect(visible).not.toContain('@example.test')
    expect((await peer.raw('GET', '/api/admin/overview')).status).toBe(403)
    expect(world.logs.join(' ')).not.toContain('@example.test')
  })

  it('requires a well-formed email at sign-up and normalises it', async () => {
    const attempt = (email: unknown) =>
      world.app.handle(new Request(`${ORIGIN}/api/auth/register`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ username: `md_e${Math.random().toString(36).slice(2, 8)}`, email, authKey: P.b64(new Uint8Array(32)) }) }), { ip: '10.8.8.8' })
    for (const bad of [undefined, '', 'not-an-email', 'a@b', 'two words@example.test', `${'x'.repeat(250)}@example.test`]) expect((await attempt(bad)).status, String(bad)).toBe(400)
    expect((await attempt('  Mixed.Case@Example.TEST ')).status).toBe(200)
    expect(await world.db.query(`SELECT 1 FROM users WHERE email = 'mixed.case@example.test'`)).toHaveLength(1)
  })

  it('audit records carry event kinds and opaque ids only', async () => {
    const rows = await world.db.query<{ detail: Record<string, unknown> }>(`SELECT detail FROM audit`)
    const allowed = new Set(['device', 'trust', 'kind', 'by', 'target', 'role', 'attempts', 'added', 'removed', 'network', 'browser'])
    for (const { detail } of rows) for (const [field, value] of Object.entries(detail)) {
      expect(allowed.has(field)).toBe(true)
      expect(String(value).length).toBeLessThanOrEqual(40)
    }
  })

  it('stores network and browser only as keyed pseudonyms, and no read receipts or presence', async () => {
    const [session] = await world.db.query(`SELECT net, agent FROM sessions LIMIT 1`)
    expect(session.net).toMatch(/^[\w-]{16}$/)
    expect(session.agent).toMatch(/^[\w-]{16}$/)
    const stored = await dump(world.db)
    expect(stored).not.toContain('TestBrowser/1.0')
    expect(stored).not.toMatch(/10\.0\.\d+\.7/)
    const tables = (await world.db.query<{ tablename: string }>(`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)).map((t) => t.tablename).sort()
    expect(tables).toEqual(['attachments', 'audit', 'challenges', 'conversations', 'devices', 'envelopes', 'members', 'prekeys', 'replays', 'sessions', 'usage_contrib', 'usage_release', 'users'])
  })

  it('error responses do not echo input or internals', async () => {
    const response = await world.app.handle(new Request(`${ORIGIN}/api/auth/login`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ username: "x' OR 1=1 --", authKey: 'short' }) }), { ip: '10.9.9.9' })
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({ error: 'Invalid input.', code: 'invalid-input' })
  })
})
