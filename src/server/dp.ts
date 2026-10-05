/**
 * Differentially private usage analytics.
 *
 * Unit of privacy: one user within one time bucket. Each user's contribution to a metric is
 * clipped when it is recorded, so removing or adding one user changes a bucket total by at most
 * the metric's cap. A bucket is released exactly once, with Laplace(cap / epsilon) noise; the noisy
 * value is stored and the per-user rows are deleted, so repeated queries cannot average the noise
 * away and the raw per-user counts stop existing.
 */
import { randomBytes } from 'node:crypto'
import type { Db } from './db'

export const METRICS = {
  messages: { cap: 20, label: 'Messages sent' },
  attachments: { cap: 5, label: 'Attachments shared' },
  logins: { cap: 3, label: 'Sign-ins' },
  alerts: { cap: 3, label: 'Security signals' },
  active_users: { cap: 1, label: 'Active users' },
} as const
export type Metric = keyof typeof METRICS
type RecordedMetric = Exclude<Metric, 'active_users'>

/** Uniform in the open interval (0, 1) from the OS CSPRNG, 53 bits of precision. */
export function secureUniform() {
  const bytes = randomBytes(7)
  const value = (bytes.readUIntBE(0, 6) * 32 + (bytes[6] >>> 3)) / 2 ** 53
  return value === 0 ? Number.MIN_VALUE : value
}

export function laplace(scale: number, uniform: () => number = secureUniform) {
  const u = uniform() - 0.5
  return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u))
}

export function createAnalytics(db: Db, options: { epsilon: number; windowMs: number }) {
  const bucketOf = (time: number) => Math.floor(time / options.windowMs)

  /** Clipping happens at write time: the server never holds more than `cap` per user, metric and bucket. */
  async function record(userId: string, metric: RecordedMetric, now = Date.now()) {
    await db.query(
      `INSERT INTO usage_contrib(bucket, user_id, metric, n) VALUES ($1, $2, $3, 1)
       ON CONFLICT (bucket, user_id, metric) DO UPDATE SET n = LEAST(usage_contrib.n + 1, $4)`,
      [bucketOf(now), userId, metric, METRICS[metric].cap],
    )
  }

  /** Releases every closed bucket in the look-back window, including empty ones. */
  async function release(now = Date.now(), lookback = 14) {
    const current = bucketOf(now)
    const done = new Set(
      (await db.query<{ bucket: number }>(`SELECT DISTINCT bucket FROM usage_release WHERE bucket >= $1`, [current - lookback])).map(
        (r) => r.bucket,
      ),
    )
    for (let bucket = current - lookback; bucket < current; bucket++) {
      if (done.has(bucket)) continue
      await db.tx(async (tx) => {
        const sums = await tx.query<{ metric: RecordedMetric; total: number }>(
          `SELECT metric, SUM(n)::int AS total FROM usage_contrib WHERE bucket = $1 GROUP BY metric`,
          [bucket],
        )
        const [{ users }] = await tx.query<{ users: number }>(
          `SELECT COUNT(DISTINCT user_id)::int AS users FROM usage_contrib WHERE bucket = $1`,
          [bucket],
        )
        const truth: Record<string, number> = { active_users: users }
        for (const row of sums) truth[row.metric] = row.total
        for (const metric of Object.keys(METRICS) as Array<Metric>) {
          const noisy = (truth[metric] ?? 0) + laplace(METRICS[metric].cap / options.epsilon)
          await tx.query(
            `INSERT INTO usage_release(bucket, metric, value, epsilon, released) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING`,
            [bucket, metric, noisy, options.epsilon, now],
          )
        }
        await tx.query(`DELETE FROM usage_contrib WHERE bucket = $1`, [bucket])
      })
    }
    // Anything older than the window can no longer be released; drop it rather than keep raw rows.
    await db.query(`DELETE FROM usage_contrib WHERE bucket < $1`, [current - lookback])
  }

  async function report(now = Date.now()) {
    await release(now)
    const rows = await db.query<{ bucket: number; metric: Metric; value: number; epsilon: number }>(
      `SELECT bucket, metric, value, epsilon FROM usage_release WHERE bucket >= $1 ORDER BY bucket`,
      [bucketOf(now) - 14],
    )
    const metricCount = Object.keys(METRICS).length
    return {
      windowMs: options.windowMs,
      epsilonPerMetric: options.epsilon,
      // Sequential composition: one user's worst-case loss for everything published about a bucket.
      epsilonPerBucket: options.epsilon * metricCount,
      metrics: Object.entries(METRICS).map(([id, m]) => ({
        id,
        label: m.label,
        cap: m.cap,
        noiseScale: m.cap / options.epsilon,
      })),
      // Rounding and clamping are post-processing and do not weaken the guarantee.
      series: rows.map((r) => ({
        start: r.bucket * options.windowMs,
        metric: r.metric,
        value: Math.max(0, Math.round(r.value)),
      })),
    }
  }

  return { record, release, report, bucketOf }
}
export type Analytics = ReturnType<typeof createAnalytics>
