/**
 * Assurance: the server and database cannot read protected content; replay, tampering and
 * ephemeral expiry behave as designed. Every test drives the real client engine against the real relay.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import * as P from '~/shared/protocol'
import { createWorld, dump, signUp, tick, useClock } from './harness'
import type { TestClient, World } from './harness'

const SECRET_TEXT = 'SENTINEL-plaintext-the-harbour-meeting-is-at-nine'
const SECRET_FILE_NAME = 'SENTINEL-board-minutes.pdf'
const SECRET_FILE_BODY = 'SENTINEL-file-body-quarterly-numbers'
const SECRET_GROUP_NAME = 'SENTINEL-group-name-merger-team'

let world: World
let alice: TestClient
let bob: TestClient
let carol: TestClient
let direct: string
let group: string

beforeAll(async () => {
  useClock()
  world = await createWorld()
  alice = await signUp(world, 'alice')
  bob = await signUp(world, 'bob')
  carol = await signUp(world, 'carol')
  direct = await alice.messenger.createConversation('direct', [bob.me.user.id])
  group = await alice.messenger.createConversation('group', [bob.me.user.id, carol.me.user.id], SECRET_GROUP_NAME)
})
afterAll(() => world.close())

describe('end-to-end delivery', () => {
  it('delivers one-to-one messages in both directions', async () => {
    await alice.messenger.send(direct, SECRET_TEXT)
    await bob.sync()
    expect(bob.texts(direct)).toEqual([SECRET_TEXT])
    await bob.messenger.send(direct, 'reply from bob')
    await alice.sync()
    expect(alice.texts(direct)).toEqual([SECRET_TEXT, 'reply from bob'])
  })

  it('delivers group messages to every member and carries the group name inside the ciphertext', async () => {
    await bob.sync()
    await carol.sync()
    await bob.messenger.send(group, 'hello group')
    await alice.sync()
    await carol.sync()
    expect(alice.texts(group)).toEqual(['hello group'])
    expect(carol.texts(group)).toEqual(['hello group'])
    for (const client of [alice, bob, carol]) expect(client.messenger.conversations.find((c) => c.id === group)!.title).toBe(SECRET_GROUP_NAME)
  })

  it('encrypts attachments, including the filename, and lets members open them', async () => {
    const bytes = new TextEncoder().encode(SECRET_FILE_BODY)
    await alice.messenger.send(group, 'see attached', { file: { name: SECRET_FILE_NAME, type: 'application/pdf', bytes } })
    await bob.sync()
    const received = bob.messenger.messages(group).find((m) => m.file)!
    expect(received.file!.name).toBe(SECRET_FILE_NAME)
    expect(new TextDecoder().decode(await bob.messenger.openAttachment(group, received.file!))).toBe(SECRET_FILE_BODY)
  })
})

describe('the server and database cannot read protected content', () => {
  it('holds no plaintext, filename, group name, private key, password-derived vault key or raw IP', async () => {
    // Leave ciphertext queued so the dump includes live message rows.
    await alice.messenger.send(direct, `${SECRET_TEXT} again`)
    const stored = await dump(world.db)
    expect(stored).toContain('envelopes.body=')
    expect(stored).toContain('attachments.data=')
    for (const secret of [SECRET_TEXT, SECRET_FILE_NAME, SECRET_FILE_BODY, SECRET_GROUP_NAME]) {
      expect(stored).not.toContain(secret)
      expect(stored).not.toContain(Buffer.from(secret).toString('base64').slice(0, 24))
    }
    for (const client of [alice, bob, carol]) {
      const k = client.vault.keys
      for (const priv of [k.ik.priv, k.dh.priv, k.spk.priv, ...Object.values(k.opks).map((o) => o.priv)]) expect(stored).not.toContain(priv)
      // The login secret is stored only as a salted scrypt hash, and addresses only as keyed pseudonyms.
      expect(stored).not.toContain(client.authKey)
      expect(stored).not.toContain(client.ip)
      expect(stored).not.toContain(client.totpSecret)
    }
    await bob.sync()
  })

  it('writes nothing sensitive to server logs', () => {
    const logs = world.logs.join('\n')
    expect(logs).toContain('"route":"/api/messages"')
    for (const secret of [SECRET_TEXT, SECRET_FILE_NAME, SECRET_FILE_BODY, SECRET_GROUP_NAME, alice.authKey, alice.cookie.split('=')[1], alice.csrf]) expect(logs).not.toContain(secret)
    // Routes are logged as patterns, so conversation, device and user ids do not appear either.
    for (const identifier of [direct, group, alice.me.user.id, bob.vault.keys.deviceId, 'alice']) expect(logs).not.toContain(identifier)
  })

  it('deletes queued ciphertext once the recipient device acknowledges it', async () => {
    await alice.messenger.send(direct, 'ack me')
    const before = await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [bob.vault.keys.deviceId])
    expect(before.length).toBeGreaterThan(0)
    await bob.sync()
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE recipient = $1`, [bob.vault.keys.deviceId])).toHaveLength(0)
  })

  it('reveals only a coarse size class: short and medium messages produce identical ciphertext lengths', async () => {
    await alice.messenger.send(direct, 'ok')
    await alice.messenger.send(direct, 'a noticeably longer message that still fits inside one padding bucket')
    const rows = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE recipient = $1 ORDER BY created`, [bob.vault.keys.deviceId])
    const lengths = rows.map((r) => (JSON.parse(r.body) as P.Envelope).ct.length)
    expect(new Set(lengths).size).toBe(1)
    await bob.sync()
  })
})

describe('replay', () => {
  it('the relay rejects a resubmitted message and raises a security signal', async () => {
    const sent = await alice.messenger.send(direct, 'only once')
    const [row] = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE id = $1`, [sent.id])
    const e: P.Envelope = JSON.parse(row.body)
    const replayed = { id: e.id, conv: e.conv, created: e.created, expires: e.expires, envelopes: [{ to: e.to, header: e.header, pre: e.pre, nonce: e.nonce, ct: e.ct }] }
    const response = await alice.raw('POST', '/api/messages', replayed)
    expect(response.status).toBe(409)
    expect((await response.json()).code).toBe('replay')
    const security = await alice.api('GET', '/api/security')
    expect(security.events.some((x: any) => x.kind === 'message.replay_blocked')).toBe(true)
    await bob.sync()
    // Still rejected after the recipient has acknowledged and the ciphertext row is gone.
    expect((await alice.raw('POST', '/api/messages', replayed)).status).toBe(409)
  })

  it('a malicious relay re-delivering an old envelope cannot make the client show it twice', async () => {
    const sent = await alice.messenger.send(direct, 'no duplicates')
    const [row] = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE id = $1`, [sent.id])
    const captured: P.Envelope = JSON.parse(row.body)
    await bob.sync()
    const count = bob.texts(direct).filter((t) => t === 'no duplicates').length
    await bob.messenger.receive([captured])
    // Same id under a fresh id is not accepted either: the id is bound into the AEAD.
    await bob.messenger.receive([{ ...captured, id: P.uuid() }])
    expect(bob.texts(direct).filter((t) => t === 'no duplicates')).toHaveLength(count)
  })

  it('rejects messages whose timestamp is outside the acceptance window', async () => {
    const stale = { id: P.uuid(), conv: direct, created: Date.now() - 10 * 60_000, expires: Date.now() + 60_000, envelopes: [{ to: bob.vault.keys.deviceId, header: { dh: bob.vault.keys.dh.pub, pn: 0, n: 0 }, pre: null, nonce: P.b64(new Uint8Array(24)), ct: P.b64(new Uint8Array(272)) }] }
    const response = await alice.raw('POST', '/api/messages', stale)
    expect(response.status).toBe(400)
    expect((await response.json()).code).toBe('stale')
  })
})

describe('tampering by the relay or database', () => {
  async function tamper(change: (e: P.Envelope) => P.Envelope) {
    const sent = await alice.messenger.send(direct, 'integrity matters')
    const [row] = await world.db.query<{ body: string }>(`SELECT body FROM envelopes WHERE id = $1`, [sent.id])
    await world.db.query(`UPDATE envelopes SET body = $1 WHERE id = $2`, [JSON.stringify(change(JSON.parse(row.body))), sent.id])
    const notices = bob.vault.notices.length
    const messages = [direct, group].map((conv) => bob.messenger.messages(conv).length)
    await bob.sync()
    expect([direct, group].map((conv) => bob.messenger.messages(conv).length)).toEqual(messages)
    expect(bob.vault.notices.length).toBe(notices + 1)
    expect(bob.vault.notices.at(-1)!.kind).toBe('warning')
  }
  const flip = (value: string) => {
    const bytes = P.unb64(value)
    bytes[bytes.length - 1] ^= 1
    return P.b64(bytes)
  }

  it('detects a modified ciphertext', () => tamper((e) => ({ ...e, ct: flip(e.ct) })))
  it('detects a modified expiry (extending an ephemeral message)', () => tamper((e) => ({ ...e, expires: e.expires + 86_400_000 })))
  it('detects a message moved into another conversation', () => tamper((e) => ({ ...e, conv: group })))
  it('detects a forged sender device', () => tamper((e) => ({ ...e, from: carol.vault.keys.deviceId })))

  it('keeps working after tampering: the ratchet state was not corrupted', async () => {
    await alice.messenger.send(direct, 'still fine')
    await bob.sync()
    expect(bob.texts(direct).at(-1)).toBe('still fine')
    await bob.messenger.send(direct, 'and back')
    await alice.sync()
    expect(alice.texts(direct).at(-1)).toBe('and back')
  })

  it('detects a modified attachment', async () => {
    await alice.messenger.send(direct, 'file', { file: { name: 'a.bin', type: 'application/octet-stream', bytes: new Uint8Array(2000).fill(9) } })
    await bob.sync()
    const file = bob.messenger.messages(direct).findLast((m) => m.file)!.file!
    await world.db.query(`UPDATE attachments SET data = $1 WHERE id = $2`, [new Uint8Array(2016).fill(1), file.id])
    await expect(bob.messenger.openAttachment(direct, file)).rejects.toThrow(/digest/)
  })
})

describe('ephemeral messages', () => {
  it('expires on the client and is purged from the server', async () => {
    const sent = await alice.messenger.send(direct, 'self-destructs', { lifetimeSeconds: 60 })
    await bob.sync()
    expect(bob.texts(direct)).toContain('self-destructs')
    await alice.messenger.send(direct, 'never fetched', { lifetimeSeconds: 60, file: { name: 'x', type: 'x', bytes: new Uint8Array(10) } })
    tick(3 * 60_000)
    await alice.messenger.expire()
    await bob.messenger.expire()
    expect(alice.texts(direct)).not.toContain('self-destructs')
    expect(bob.texts(direct)).not.toContain('self-destructs')
    expect(JSON.stringify(bob.saved)).not.toContain('self-destructs')
    await world.app.sweep(true)
    expect(await world.db.query(`SELECT 1 FROM envelopes WHERE expires < $1`, [Date.now()])).toHaveLength(0)
    expect(await world.db.query(`SELECT 1 FROM attachments WHERE expires < $1`, [Date.now()])).toHaveLength(0)
    // The replay tombstone outlives the message, so an expired id cannot be reintroduced.
    expect(await world.db.query(`SELECT 1 FROM replays WHERE hash IS NOT NULL`)).not.toHaveLength(0)
    await bob.sync()
    expect(bob.texts(direct)).not.toContain('never fetched')
    expect(sent.expires).toBeLessThan(Date.now())
  })

  it('refuses lifetimes longer than seven days', async () => {
    await expect(alice.messenger.send(direct, 'forever', { lifetimeSeconds: 30 * 86_400 })).rejects.toThrow(/lifetime/)
  })
})
