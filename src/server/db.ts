/**
 * One small query interface over two Postgres engines:
 * - node-postgres when DATABASE_URL is set (Neon in production, any Postgres in CI)
 * - PGlite (in-process Postgres) for local development and tests, so no database server is needed
 */
export interface Db {
  query: <T = Record<string, any>>(sql: string, params?: Array<unknown>) => Promise<Array<T>>
  tx: <T>(fn: (db: Db) => Promise<T>) => Promise<T>
  close: () => Promise<void>
}

const INT8 = 20

export async function openPg(connectionString: string): Promise<Db> {
  const pg = (await import('pg')).default
  pg.types.setTypeParser(INT8, Number)
  const pool = new pg.Pool({ connectionString, max: 8, idleTimeoutMillis: 20_000 })
  // Neon closes idle connections; without a listener that surfaces as an unhandled 'error' event.
  pool.on('error', () => {})
  const wrap = (runner: { query: (sql: string, params?: Array<unknown>) => Promise<{ rows: Array<any> }> }): Db => ({
    query: async (sql, params) => (await runner.query(sql, params)).rows,
    tx: () => Promise.reject(new Error('Nested transactions are not supported.')),
    close: async () => {},
  })
  return {
    query: async (sql, params) => (await pool.query(sql, params)).rows,
    async tx(fn) {
      const client = await pool.connect()
      try {
        await client.query('BEGIN')
        const result = await fn(wrap(client))
        await client.query('COMMIT')
        return result
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {})
        throw error
      } finally {
        client.release()
      }
    },
    close: () => pool.end(),
  }
}

export async function openPglite(dataDir?: string): Promise<Db> {
  const { PGlite } = await import('@electric-sql/pglite')
  const lite = await PGlite.create({ dataDir, parsers: { [INT8]: Number } })
  const wrap = (runner: { query: (sql: string, params?: Array<any>) => Promise<{ rows: Array<any> }> }): Db => ({
    query: async (sql, params) => (await runner.query(sql, params as Array<any>)).rows,
    tx: () => Promise.reject(new Error('Nested transactions are not supported.')),
    close: async () => {},
  })
  return {
    query: async (sql, params) => (await lite.query(sql, params as Array<any>)).rows as Array<any>,
    tx: (fn) => lite.transaction((tx) => fn(wrap(tx))) as Promise<any>,
    close: () => lite.close(),
  }
}

/** Timestamps are epoch milliseconds in BIGINT columns. All statements are idempotent. */
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    auth_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'pending',
    totp TEXT NOT NULL,
    totp_step BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    ik TEXT NOT NULL,
    dh TEXT NOT NULL,
    dh_sig TEXT NOT NULL,
    spk_id INTEGER NOT NULL,
    spk TEXT NOT NULL,
    spk_sig TEXT NOT NULL,
    spk_at BIGINT NOT NULL,
    trust TEXT NOT NULL,
    xsig_by TEXT,
    xsig TEXT,
    created BIGINT NOT NULL,
    seen BIGINT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id)`,
  `CREATE TABLE IF NOT EXISTS prekeys (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    pub TEXT NOT NULL,
    PRIMARY KEY (device_id, id))`,
  `CREATE TABLE IF NOT EXISTS sessions (
    hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created BIGINT NOT NULL,
    expires BIGINT NOT NULL,
    seen BIGINT NOT NULL,
    stepup BIGINT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    net TEXT NOT NULL,
    agent TEXT NOT NULL,
    risk INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)`,
  `CREATE TABLE IF NOT EXISTS challenges (
    hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enroll BOOLEAN NOT NULL,
    expires BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    owner TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    roster JSONB NOT NULL,
    signer TEXT NOT NULL,
    sig TEXT NOT NULL,
    created BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS members (
    conv TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (conv, user_id))`,
  `CREATE INDEX IF NOT EXISTS members_user ON members(user_id)`,
  `CREATE TABLE IF NOT EXISTS envelopes (
    id TEXT NOT NULL,
    recipient TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    conv TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created BIGINT NOT NULL,
    expires BIGINT NOT NULL,
    PRIMARY KEY (id, recipient))`,
  `CREATE INDEX IF NOT EXISTS envelopes_recipient ON envelopes(recipient, created)`,
  `CREATE TABLE IF NOT EXISTS replays (hash TEXT PRIMARY KEY, expires BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    conv TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    data BYTEA NOT NULL,
    size INTEGER NOT NULL,
    created BIGINT NOT NULL,
    expires BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS audit (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}',
    created BIGINT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, id DESC)`,
  `CREATE TABLE IF NOT EXISTS usage_contrib (
    bucket BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (bucket, user_id, metric))`,
  `CREATE TABLE IF NOT EXISTS usage_release (
    bucket BIGINT NOT NULL,
    metric TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    epsilon DOUBLE PRECISION NOT NULL,
    released BIGINT NOT NULL,
    PRIMARY KEY (bucket, metric))`,
]

export async function migrate(db: Db) {
  for (const statement of SCHEMA) await db.query(statement)
}
