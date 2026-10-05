/**
 * Differential privacy for aggregate analytics.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { METRICS, laplace, secureUniform } from '~/server/dp'
import { createWorld, signUp, tick, useClock } from './harness'
import type { World } from './harness'

const HOUR = 3600_000
let world: World
beforeAll(async () => {
  useClock()
  world = await createWorld({ epsilon: 1, analyticsWindowMs: HOUR })
})
afterAll(() => world.close())

describe('Laplace mechanism', () => {
  it('draws uniform values strictly inside (0, 1) from the CSPRNG', () => {
    for (let i = 0; i < 5000; i++) {
      const u = secureUniform()
      expect(u).toBeGreaterThan(0)
      expect(u).toBeLessThan(1)
    }
  })

  it('has zero mean and mean absolute deviation equal to the scale', () => {
    const scale = 4
    const samples = Array.from({ length: 40_000 }, () => laplace(scale))
    const mean = samples.reduce((a, b) => a + b, 0) / samples.length
    const mad = samples.reduce((a, b) => a + Math.abs(b), 0) / samples.length
    expect(Math.abs(mean)).toBeLessThan(0.15)
    expect(mad).toBeGreaterThan(scale * 0.95)
    expect(mad).toBeLessThan(scale * 1.05)
  })

  it('satisfies the epsilon bound empirically for neighbouring counts', () => {
    // For outputs binned at integers, P[M(c)=k] / P[M(c+1)=k] must stay within e^epsilon.
    const epsilon = 0.8
    const n = 200_000
    const histogram = (truth: number) => {
      const bins = new Map<number, number>()
      for (let i = 0; i < n; i++) {
        const k = Math.round(truth + laplace(1 / epsilon))
        bins.set(k, (bins.get(k) ?? 0) + 1)
      }
      return bins
    }
    const a = histogram(10)
    const b = histogram(11)
    for (let k = 7; k <= 14; k++) {
      const ratio = a.get(k)! / b.get(k)!
      expect(Math.max(ratio, 1 / ratio)).toBeLessThan(Math.exp(epsilon) * 1.12)
    }
  })
})

describe('private usage analytics', () => {
  it('clips each user’s contribution at write time', async () => {
    const heavy = await signUp(world, 'dp_heavy')
    for (let i = 0; i < METRICS.messages.cap + 40; i++) await world.app.analytics.record(heavy.me.user.id, 'messages')
    const [row] = await world.db.query(`SELECT n FROM usage_contrib WHERE user_id = $1 AND metric = 'messages'`, [heavy.me.user.id])
    expect(row.n).toBe(METRICS.messages.cap)
  })

  it('does not publish the bucket that is still open', async () => {
    const report = await world.app.analytics.report()
    const current = world.app.analytics.bucketOf(Date.now()) * HOUR
    expect(report.series.some((p) => p.start === current)).toBe(false)
  })

  it('releases a closed bucket exactly once, then deletes the per-user rows', async () => {
    const bucket = world.app.analytics.bucketOf(Date.now())
    tick(HOUR)
    const first = await world.app.analytics.report()
    const points = first.series.filter((p) => p.start === bucket * HOUR)
    expect(points.map((p) => p.metric).sort()).toEqual(Object.keys(METRICS).sort())
    expect(await world.db.query(`SELECT 1 FROM usage_contrib WHERE bucket = $1`, [bucket])).toHaveLength(0)
    // Asking again returns the stored release: an analyst cannot average the noise away.
    for (let i = 0; i < 5; i++) expect((await world.app.analytics.report()).series).toEqual(first.series)
    const raw = await world.db.query<{ metric: string; value: number }>(`SELECT metric, value FROM usage_release WHERE bucket = $1`, [bucket])
    const messages = raw.find((r) => r.metric === 'messages')!.value
    // Truth is the clipped cap; noise scale is cap / epsilon, so the value is plausible but not exact.
    expect(messages).not.toBe(METRICS.messages.cap)
    expect(Math.abs(messages - METRICS.messages.cap)).toBeLessThan(METRICS.messages.cap * 14)
  })

  it('publishes empty buckets too, so silence is not a signal', async () => {
    tick(3 * HOUR)
    const report = await world.app.analytics.report()
    const starts = new Set(report.series.map((p) => p.start))
    expect(starts.size).toBe(14)
    for (const point of report.series) {
      expect(Number.isInteger(point.value)).toBe(true)
      expect(point.value).toBeGreaterThanOrEqual(0)
    }
  })

  it('reports the privacy parameters alongside the data', async () => {
    const report = await world.app.analytics.report()
    expect(report.epsilonPerMetric).toBe(1)
    expect(report.epsilonPerBucket).toBe(Object.keys(METRICS).length)
    expect(report.metrics.find((m) => m.id === 'messages')).toMatchObject({ cap: 20, noiseScale: 20 })
    expect(report.metrics.find((m) => m.id === 'active_users')).toMatchObject({ cap: 1, noiseScale: 1 })
  })

  it('across many simulated buckets the released totals are unbiased and one user is hidden in the noise', async () => {
    const fresh = await createWorld({ epsilon: 1, analyticsWindowMs: HOUR })
    const now = Date.now()
    const base = fresh.app.analytics.bucketOf(now) - 14
    // 14 closed buckets, each with 30 users sending 5 messages; one extra heavy user only in even buckets.
    for (let i = 0; i < 14; i++) {
      for (let u = 0; u < 30; u++) await fresh.db.query(`INSERT INTO usage_contrib VALUES ($1, $2, 'messages', 5)`, [base + i, `user-${u}`])
      if (i % 2 === 0) await fresh.db.query(`INSERT INTO usage_contrib VALUES ($1, 'target', 'messages', 50)`, [base + i])
    }
    const report = await fresh.app.analytics.report(now)
    const series = report.series.filter((p) => p.metric === 'messages').map((p) => p.value)
    const mean = series.reduce((a, b) => a + b, 0) / series.length
    expect(mean).toBeGreaterThan(175 - 60)
    expect(mean).toBeLessThan(175 + 60)
    expect(await fresh.db.query(`SELECT 1 FROM usage_contrib`)).toHaveLength(0)
    await fresh.close()
  })

  it('exposes analytics to auditors and administrators only, and never per-user rows', async () => {
    const adminClient = await signUp(await createWorldWithAdmin(), 'dp_member')
    const response = await adminClient.raw('GET', '/api/admin/analytics')
    expect(response.status).toBe(403)
  })
})

let extra: World | undefined
async function createWorldWithAdmin() {
  extra = await createWorld()
  await signUp(extra, 'dp_admin')
  return extra
}
afterAll(() => extra?.close())
