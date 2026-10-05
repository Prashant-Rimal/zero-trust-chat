/**
 * Creates the Cipherroom tables in the database named by DATABASE_URL.
 * Safe to run repeatedly: every statement is CREATE ... IF NOT EXISTS.
 *
 *   npm run migrate            (reads .env)
 *   npm run migrate -- --check (only lists what is there)
 */
import { migrate, openPg } from '../src/server/db.ts'

const url = process.env.DATABASE_URL
if (!url) {
  console.error('DATABASE_URL is not set. Put it in .env or the environment.')
  process.exit(1)
}

const db = await openPg(url)
const tables = async () => (await db.query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)).map((r) => r.tablename)
try {
  const [{ version, db: name }] = await db.query(`SELECT version(), current_database() AS db`)
  console.log(`Connected to "${name}" (${version.split(' ').slice(0, 2).join(' ')})`)
  const before = await tables()
  console.log(`Tables before: ${before.length ? before.join(', ') : '(none)'}`)
  if (!process.argv.includes('--check')) {
    await migrate(db)
    const after = await tables()
    console.log(`Tables after:  ${after.join(', ')}`)
    console.log(`Created: ${after.filter((t) => !before.includes(t)).join(', ') || '(nothing new)'}`)
  }
} finally {
  await db.close()
}
