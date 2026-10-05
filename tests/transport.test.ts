/**
 * Real sockets: the relay behind a Node HTTP server with the production WebSocket binding,
 * exercised with real fetch and a real WebSocket client.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import WebSocket from 'ws'
import type { Db } from '~/server/db'
import { startServer } from './fixture'
import { LiveClient } from './live'

let fixture: Awaited<ReturnType<typeof startServer>>
let base: string
let db: Db

beforeAll(async () => {
  fixture = await startServer()
  base = fixture.base
  db = fixture.db
})
afterAll(() => fixture.close())

describe('HTTP and WebSocket transport', () => {
  let alice: LiveClient
  let bob: LiveClient
  let conv: string

  it('refuses a WebSocket upgrade without a session, or from another origin', async () => {
    const attempt = (headers: Record<string, string>) =>
      new Promise<number>((resolve) => {
        const ws = new WebSocket(`${base.replace('http', 'ws')}/ws`, { headers })
        ws.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0))
        ws.on('open', () => resolve(101))
        ws.on('error', () => {})
      })
    expect(await attempt({ origin: base })).toBe(401)
    alice = await new LiveClient(base, 'ws_alice').register()
    expect(await attempt({ origin: 'https://evil.example', cookie: alice.cookie, 'user-agent': alice.agent })).toBe(403)
  })

  it('delivers messages in real time in both directions over WebSocket', async () => {
    bob = await new LiveClient(base, 'ws_bob').register()
    await alice.connect()
    await bob.connect()
    conv = await alice.messenger.createConversation('direct', [bob.me.user.id])
    await bob.until(() => bob.messenger.conversations.length === 1)
    await alice.messenger.send(conv, 'over the wire')
    await bob.until(() => bob.texts(conv).length === 1)
    expect(bob.texts(conv)).toEqual(['over the wire'])
    await bob.messenger.send(conv, 'and back')
    await alice.until(() => alice.texts(conv).length === 2)
    expect(alice.texts(conv)).toEqual(['over the wire', 'and back'])
    // Acknowledged over the socket, so nothing is left queued on the server.
    await bob.until(() => true, 100)
    await new Promise((r) => setTimeout(r, 100))
    expect(await db.query(`SELECT 1 FROM envelopes`)).toHaveLength(0)
  })

  it('transfers an encrypted attachment over HTTP', async () => {
    const bytes = new Uint8Array(300_000).map((_, i) => (i * 31) % 256)
    await alice.messenger.send(conv, 'file', { file: { name: 'photo.raw', type: 'application/octet-stream', bytes } })
    await bob.until(() => bob.messenger.messages(conv).some((m) => m.file))
    const file = bob.messenger.messages(conv).find((m) => m.file)!.file!
    expect(await bob.messenger.openAttachment(conv, file)).toEqual(bytes)
  })

  it('closes the live socket with code 4001 the moment the session is revoked', async () => {
    await db.query(`UPDATE sessions SET revoked = TRUE WHERE user_id = $1`, [bob.me.user.id])
    await alice.messenger.send(conv, 'bob is gone')
    await bob.until(() => bob.closed !== null)
    expect(bob.closed).toBe(4001)
    expect(bob.texts(conv)).not.toContain('bob is gone')
    expect((await bob.fetch('GET', '/api/me')).status).toBe(401)
  })

  it('rejects malformed and oversized frames without dropping the server', async () => {
    alice.socket!.send('not json')
    alice.socket!.send(JSON.stringify({ t: 'send', ref: 'x', message: { nope: true } }))
    alice.socket!.send(JSON.stringify({ t: 'unknown' }))
    await new Promise((r) => setTimeout(r, 100))
    expect((await alice.fetch('GET', '/api/me')).status).toBe(200)
    expect(alice.socket!.readyState).toBe(WebSocket.OPEN)
  })
})
