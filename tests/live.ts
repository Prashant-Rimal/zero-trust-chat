/**
 * A headless Cipherroom client that talks to a running server over real HTTP and WebSocket.
 * Used by the transport test (in-process server) and by the deployment smoke test (any URL).
 */
import { randomBytes } from 'node:crypto'
import WebSocket from 'ws'
import { ApiError, Messenger, newVault } from '~/client/messenger'
import type { Me, Transport } from '~/client/messenger'
import { totp } from '~/server/crypto'
import * as P from '~/shared/protocol'

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

export class LiveClient {
  cookie = ''
  me!: Me
  vault = newVault()
  messenger!: Messenger
  socket: WebSocket | null = null
  closed: number | null = null
  authKey = P.b64(randomBytes(32))
  totpSecret = ''
  private waiting = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()
  private lastStep = 0

  constructor(
    public base: string,
    public username: string,
    public agent = 'CipherroomLiveClient/1.0',
  ) {}

  async fetch(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { 'user-agent': this.agent }
    if (this.cookie) headers.cookie = this.cookie
    if (method !== 'GET') {
      headers.origin = this.base
      if (this.me) headers['x-csrf-token'] = this.me.csrf
    }
    const binary = body instanceof Uint8Array
    if (body !== undefined && !binary) headers['content-type'] = 'application/json'
    const response = await fetch(this.base + path, { method, headers, body: body === undefined ? undefined : binary ? (body as BodyInit) : JSON.stringify(body) })
    const cookie = response.headers.getSetCookie().find((c) => c.startsWith('cr_session='))
    if (cookie) this.cookie = cookie.split(';')[0]
    return response
  }
  api = async <T = any>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await this.fetch(method, path, body)
    const data = await response.json()
    if (!response.ok) throw new ApiError(response.status, data.error, data.code)
    return data
  }
  transport: Transport = {
    api: this.api,
    upload: (path, bytes) => this.api('POST', path, bytes),
    download: async (path) => new Uint8Array(await (await this.fetch('GET', path)).arrayBuffer()),
    send: (message: any) => {
      if (this.socket?.readyState !== WebSocket.OPEN) return null
      if (message.t === 'ack') return (this.socket.send(JSON.stringify(message)), Promise.resolve(true))
      const ref = P.uuid()
      return new Promise((resolve, reject) => {
        this.waiting.set(ref, { resolve, reject })
        this.socket!.send(JSON.stringify({ t: 'send', ref, message }))
      })
    },
  }

  /** Real time cannot be skipped here, so wait for a TOTP step the server has not seen yet. */
  async code() {
    while (Math.floor(Date.now() / 30000) <= this.lastStep) await sleep(500)
    this.lastStep = Math.floor(Date.now() / 30000)
    return totp(this.totpSecret)
  }

  async register() {
    const result = await this.api('POST', '/api/auth/register', { username: this.username, email: `${this.username}@example.test`, authKey: this.authKey })
    this.totpSecret = result.secret
    return this.verify(result.challenge)
  }
  async login() {
    const { challenge } = await this.api('POST', '/api/auth/login', { username: this.username, authKey: this.authKey })
    return this.verify(challenge)
  }
  private async verify(challenge: string) {
    this.me = await this.api('POST', '/api/auth/verify', Messenger.enrolment(this.vault, challenge, await this.code(), 'Headless client'))
    this.messenger = new Messenger(this.vault, this.transport, async () => {})
    await this.messenger.start(this.me)
    return this
  }

  connect() {
    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(`${this.base.replace(/^http/, 'ws')}/ws`, { headers: { cookie: this.cookie, origin: this.base, 'user-agent': this.agent } })
      this.socket = ws
      ws.on('unexpected-response', (_req, res) => reject(new Error(`WebSocket upgrade refused: ${res.statusCode}`)))
      ws.on('error', reject)
      ws.on('close', (code) => (this.closed = code))
      ws.on('message', (data) => {
        const frame = JSON.parse(data.toString())
        if (frame.t === 'ready') resolve()
        else if (frame.t === 'envelope') void this.messenger.receive([frame.e])
        else if (frame.t === 'sync' && frame.what === 'conversations') void this.messenger.refresh()
        else if (frame.t === 'sent') {
          const waiter = this.waiting.get(frame.ref)
          this.waiting.delete(frame.ref)
          if (frame.ok) waiter?.resolve(frame)
          else waiter?.reject(new ApiError(frame.status, frame.error, frame.code))
        }
      })
    })
  }

  async until(condition: () => boolean, timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
      if (Date.now() > deadline) throw new Error('Timed out waiting for condition.')
      await sleep(25)
    }
  }
  texts(conv: string) {
    return this.messenger.messages(conv).map((m) => m.text)
  }
}
