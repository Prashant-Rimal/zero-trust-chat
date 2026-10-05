import { randomBytes } from 'node:crypto'
import { vi } from 'vitest'
import { ApiError, Messenger, newVault } from '~/client/messenger'
import type { Me, Transport, VaultState } from '~/client/messenger'
import { createApp } from '~/server/app'
import type { App } from '~/server/app'
import { totp } from '~/server/crypto'
import { migrate, openPg, openPglite } from '~/server/db'
import type { Db } from '~/server/db'
import * as P from '~/shared/protocol'

export const ORIGIN = 'http://test.local'

/** Only `Date` is faked, so TOTP steps and expiries can be advanced without real waiting. */
export function useClock() {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() })
}
export const tick = (ms: number) => vi.setSystemTime(Date.now() + ms)

export type World = { app: App; db: Db; logs: Array<string>; close: () => Promise<void> }

export async function createWorld(options: { epsilon?: number; analyticsWindowMs?: number } = {}): Promise<World> {
  // TEST_DATABASE_URL lets CI run the same suite against real Postgres; default is in-process PGlite.
  const url = process.env.TEST_DATABASE_URL
  const db = url ? await openPg(url) : await openPglite()
  if (url) await db.query(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
  await migrate(db)
  const logs: Array<string> = []
  const app = createApp({ db, secret: randomBytes(32), origin: ORIGIN, log: (line) => logs.push(line), ...options })
  return { app, db, logs, close: () => db.close() }
}

let addresses = 10

export class TestClient {
  cookie = ''
  csrf = ''
  ip = `10.0.${addresses++}.7`
  agent = 'TestBrowser/1.0'
  origin = ORIGIN
  authKey = P.b64(randomBytes(32))
  totpSecret = ''
  me!: Me
  vault: VaultState = newVault()
  saved: VaultState | null = null
  messenger!: Messenger
  socket: { frames: Array<any>; closed: { code: number; reason: string } | null; message: (raw: string) => Promise<void>; close: () => void } | null = null

  constructor(
    public world: World,
    public username: string,
  ) {}

  async raw(method: string, path: string, body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { 'user-agent': this.agent, ...extra }
    if (this.cookie) headers.cookie = this.cookie
    if (method !== 'GET') {
      headers.origin = this.origin
      if (this.csrf) headers['x-csrf-token'] = this.csrf
    }
    const binary = body instanceof Uint8Array
    if (body !== undefined && !binary) headers['content-type'] = 'application/json'
    const response = await this.world.app.handle(
      new Request(`${ORIGIN}${path}`, { method, headers, body: body === undefined ? undefined : binary ? (body as BodyInit) : JSON.stringify(body) }),
      { ip: this.ip },
    )
    const setCookie = response.headers.get('set-cookie')
    if (setCookie) this.cookie = setCookie.split(';')[0]
    return response
  }

  api = async <T = any>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await this.raw(method, path, body)
    const data = await response.json()
    if (!response.ok) throw new ApiError(response.status, data.error, data.code)
    return data
  }

  transport: Transport = {
    api: this.api,
    upload: async (path, bytes) => this.api('POST', path, bytes),
    download: async (path) => {
      const response = await this.raw('GET', path)
      if (!response.ok) throw new ApiError(response.status, (await response.json()).error)
      return new Uint8Array(await response.arrayBuffer())
    },
  }

  /** A fresh, never-used TOTP code. Advances the fake clock one step so codes are never reused by accident. */
  code() {
    tick(30_000)
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
  async verify(challenge: string, code = this.code()) {
    this.me = await this.api('POST', '/api/auth/verify', Messenger.enrolment(this.vault, challenge, code, `${this.username}'s device`))
    this.csrf = this.me.csrf
    this.messenger = new Messenger(this.vault, this.transport, async (vault) => {
      this.saved = structuredClone(vault)
    })
    await this.messenger.start(this.me)
    return this
  }
  stepUp() {
    return this.api('POST', '/api/auth/stepup', { code: this.code() })
  }

  /** Opens a realtime connection through the same entry point the WebSocket server uses. */
  async connect() {
    const frames: Array<any> = []
    const state = { frames, closed: null as { code: number; reason: string } | null }
    const handle = await this.world.app.realtime.connect(
      { cookie: this.cookie, origin: this.origin, ip: this.ip, agent: this.agent },
      { send: (data) => void frames.push(JSON.parse(data)), close: (code, reason) => void (state.closed = { code, reason }) },
    )
    this.socket = Object.assign(state, { message: handle.message, close: handle.close })
    return this.socket
  }

  /** Pulls queued ciphertext, as the app does on connect. */
  sync() {
    return this.messenger.sync()
  }
  texts(conv: string) {
    return this.messenger.messages(conv).map((m) => m.text)
  }
}

export async function signUp(world: World, username: string) {
  return new TestClient(world, username).register()
}

/** A second device for the same account: same credentials and TOTP seed, new vault and keys. */
export async function secondDevice(first: TestClient) {
  const next = new TestClient(first.world, first.username)
  next.authKey = first.authKey
  next.totpSecret = first.totpSecret
  await next.login()
  return next
}

export async function approve(approver: TestClient, pending: TestClient) {
  await approver.stepUp()
  await approver.messenger.approveDevice({ id: pending.vault.keys.deviceId, ik: pending.vault.keys.ik.pub })
  pending.me = await pending.api('GET', '/api/me')
  await pending.messenger.start(pending.me)
}

/** Lets fire-and-forget realtime deliveries settle. */
export const settle = () => new Promise((resolve) => setTimeout(resolve, 25))

/** Everything a database thief (or the operator) would hold, as one searchable string. */
export async function dump(db: Db) {
  const tables = await db.query<{ tablename: string }>(`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
  let out = ''
  for (const { tablename } of tables) {
    for (const row of await db.query(`SELECT * FROM ${tablename}`)) {
      for (const [column, value] of Object.entries(row)) {
        const text = value instanceof Uint8Array ? Buffer.from(value).toString('latin1') : typeof value === 'object' ? JSON.stringify(value) : String(value)
        out += `${tablename}.${column}=${text}\n`
      }
    }
  }
  return out
}
