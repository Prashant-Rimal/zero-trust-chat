/**
 * Process-wide singleton wiring for the relay: environment, database, secret.
 * Kept on globalThis so the Vite dev server, the SSR module graph and the production entry
 * all share one database handle and one realtime hub.
 */
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createApp } from './app'
import type { App } from './app'
import { migrate, openPg, openPglite } from './db'

const globals = globalThis as { __cipherroom?: Promise<App> }

export const config = () => ({
  origin: (process.env.APP_ORIGIN ?? 'http://localhost:3000').replace(/\/$/, ''),
  databaseUrl: process.env.DATABASE_URL,
  dataDir: process.env.DATA_DIR ?? join(process.cwd(), 'data'),
  trustProxy: process.env.TRUST_PROXY === '1',
  production: process.env.NODE_ENV === 'production',
  epsilon: Number(process.env.DP_EPSILON ?? 1),
  analyticsWindowMs: Number(process.env.DP_WINDOW_MINUTES ?? 1440) * 60_000,
})

function loadSecret(c: ReturnType<typeof config>) {
  if (process.env.SERVER_SECRET) {
    const secret = Buffer.from(process.env.SERVER_SECRET, 'base64')
    if (secret.length !== 32) throw new Error('SERVER_SECRET must be 32 random bytes, base64-encoded.')
    return secret
  }
  if (c.production || c.databaseUrl) throw new Error('SERVER_SECRET is required when NODE_ENV=production or DATABASE_URL is set.')
  // Local development only: generate once and keep beside the local database.
  const file = join(c.dataDir, 'server-secret')
  if (!existsSync(file)) {
    mkdirSync(c.dataDir, { recursive: true })
    writeFileSync(file, randomBytes(32).toString('base64'), { mode: 0o600 })
  }
  return Buffer.from(readFileSync(file, 'utf8'), 'base64')
}

async function boot() {
  const c = config()
  const secret = loadSecret(c)
  if (!c.databaseUrl) mkdirSync(c.dataDir, { recursive: true })
  const db = c.databaseUrl ? await openPg(c.databaseUrl) : await openPglite(join(c.dataDir, 'pglite'))
  await migrate(db)
  return createApp({ db, secret, origin: c.origin, epsilon: c.epsilon, analyticsWindowMs: c.analyticsWindowMs })
}

export function getApp() {
  return (globals.__cipherroom ??= boot().catch((error) => {
    delete globals.__cipherroom
    throw error
  }))
}

/**
 * The peer address, or with TRUST_PROXY=1 the address appended by the nearest proxy.
 * The left-most X-Forwarded-For entries are client-controlled and are never used.
 */
export function clientIp(peer: string | undefined, forwardedFor: string | null | undefined) {
  if (config().trustProxy && forwardedFor) return forwardedFor.split(',').at(-1)!.trim()
  return peer ?? 'unknown'
}
