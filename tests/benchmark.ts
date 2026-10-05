/**
 * Measures the cost of the security design: key derivation, session setup, per-message
 * encryption, ciphertext expansion, group fan-out, attachment throughput and end-to-end latency
 * over real HTTP/WebSocket. Writes evidence/benchmark.json.   npm run benchmark
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { cpus } from 'node:os'
import { expect, it } from 'vitest'
import * as P from '~/shared/protocol'
import { startServer } from './fixture'
import { LiveClient } from './live'

const round = (value: number, digits = 3) => Number(value.toFixed(digits))
function stats(samples: Array<number>) {
  const sorted = [...samples].sort((a, b) => a - b)
  const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]
  return { n: sorted.length, mean: round(sorted.reduce((a, b) => a + b, 0) / sorted.length), p50: round(at(0.5)), p95: round(at(0.95)), max: round(sorted.at(-1)!) }
}
function time(iterations: number, work: (i: number) => void) {
  for (let i = 0; i < Math.min(50, iterations); i++) work(i) // warm-up
  const samples: Array<number> = []
  for (let i = 0; i < iterations; i++) {
    const start = performance.now()
    work(i)
    samples.push(performance.now() - start)
  }
  return stats(samples)
}

const pub = (k: P.DeviceKeys): P.PublicDevice => ({ id: k.deviceId, userId: 'u', label: '', ik: k.ik.pub, dh: k.dh.pub, dhSig: k.dhSig, trust: 'trusted', xsig: null, created: 0 })
const context = (from: string, to: string): P.EnvelopeContext => ({ id: P.uuid(), conv: P.uuid(), from, to, created: Date.now(), expires: Date.now() + 86_400_000 })
function session() {
  const a = P.generateDeviceKeys()
  const b = P.generateDeviceKeys()
  const sa = P.initiateSession(a, pub(b), { spk: P.publicSpk(b), opk: P.mintOneTimePrekeys(b, 1)[0] })
  const first = P.ratchetEncrypt(sa, context(a.deviceId, b.deviceId), new Uint8Array(1))
  const sb = P.ratchetDecrypt(P.acceptSession(b, pub(a), first.pre!), first).session
  return { a, b, sa, sb }
}

it('benchmark', async () => {
  const results: Record<string, unknown> = {
    generated: new Date().toISOString(),
    environment: { node: process.version, cpu: cpus()[0]?.model, platform: process.platform, note: 'Single machine, loopback network, in-process PGlite. Treat as relative costs, not capacity figures.' },
  }

  // --- one-off costs ---
  const kdf: Array<number> = []
  for (let i = 0; i < 3; i++) {
    const start = performance.now()
    await P.deriveKeys('bench', 'correct horse battery staple')
    kdf.push(performance.now() - start)
  }
  const peer = P.generateDeviceKeys()
  const bundle = { spk: P.publicSpk(peer), opk: null }
  const me = P.generateDeviceKeys()
  results.setup_ms = {
    'password KDF (PBKDF2-SHA256, 600k iterations) — once per unlock': stats(kdf),
    'device key generation (Ed25519 + 2×X25519 + signatures)': time(100, () => void P.generateDeviceKeys()),
    'X3DH session initiation (verify 2 signatures + 3 DH)': time(200, () => void P.initiateSession(me, pub(peer), bundle)),
    'security code (5200× SHA-256)': time(50, (i) => void P.userFingerprint(`u${i}`, [me.ik.pub])),
  }

  // --- per-message cost and size ---
  const perMessage: Record<string, unknown> = {}
  for (const size of [32, 256, 1024, 8192]) {
    const { a, b, sa } = session()
    let sb = session().sb
    const plaintext = new Uint8Array(size).fill(65)
    const pairs = session()
    const encrypted: Array<P.Envelope> = []
    const encrypt = time(2000, () => void encrypted.push(P.ratchetEncrypt(pairs.sa, context(pairs.a.deviceId, pairs.b.deviceId), plaintext)))
    sb = pairs.sb
    let index = 50 // skip warm-up envelopes in order
    for (let i = 0; i < 50; i++) sb = P.ratchetDecrypt(sb, encrypted[i]).session
    const decrypt = time(1900, () => {
      sb = P.ratchetDecrypt(sb, encrypted[index++]).session
    })
    const baseline = time(2000, () => void JSON.stringify({ text: P.b64(plaintext) }))
    const envelope = P.ratchetEncrypt(sa, context(a.deviceId, b.deviceId), plaintext)
    const wire = JSON.stringify(envelope).length
    perMessage[`${size} B plaintext`] = {
      encrypt_ms: encrypt,
      decrypt_ms: decrypt,
      plaintext_serialise_baseline_ms: baseline,
      wire_bytes: wire,
      ciphertext_bytes: P.unb64(envelope.ct).length,
      expansion_factor: round(wire / size, 2),
    }
  }
  results.per_message = perMessage

  // --- a full DH ratchet turn (reply after receiving) ---
  {
    let { a, b, sa, sb } = session()
    const samples: Array<number> = []
    for (let i = 0; i < 300; i++) {
      const start = performance.now()
      const out = P.ratchetEncrypt(sb, context(b.deviceId, a.deviceId), new Uint8Array(64))
      sa = P.ratchetDecrypt(sa, out).session
      const back = P.ratchetEncrypt(sa, context(a.deviceId, b.deviceId), new Uint8Array(64))
      sb = P.ratchetDecrypt(sb, back).session
      samples.push((performance.now() - start) / 2)
    }
    results.ratchet_turn_ms = { 'encrypt + decrypt including a DH ratchet step (new key pair + 2 DH)': stats(samples) }
  }

  // --- group fan-out: one message encrypted separately for N recipient devices ---
  const fanout: Record<string, unknown> = {}
  for (const devices of [1, 5, 10, 25, 50]) {
    const sessions = Array.from({ length: devices }, () => session())
    const plaintext = new Uint8Array(200)
    fanout[`${devices} recipient devices`] = time(200, () => {
      for (const s of sessions) P.ratchetEncrypt(s.sa, context(s.a.deviceId, s.b.deviceId), plaintext)
    })
  }
  results.group_fanout_encrypt_ms = fanout

  // --- attachments ---
  const attachments: Record<string, unknown> = {}
  for (const megabytes of [0.25, 1, 4]) {
    const bytes = new Uint8Array(megabytes * 1024 * 1024).fill(7)
    const enc = P.encryptAttachment('c', bytes)
    const encrypt = time(8, () => void P.encryptAttachment('c', bytes))
    const decrypt = time(8, () => void P.decryptAttachment('c', enc, enc.ciphertext))
    attachments[`${megabytes} MB`] = { encrypt_ms: encrypt, decrypt_and_verify_ms: decrypt, throughput_mb_per_s: round(megabytes / (encrypt.mean / 1000), 1), overhead_bytes: enc.ciphertext.length - bytes.length }
  }
  results.attachments = attachments

  // --- end to end over real HTTP + WebSocket ---
  const fixture = await startServer()
  try {
    const alice = await new LiveClient(fixture.base, 'bench_alice').register()
    const bob = await new LiveClient(fixture.base, 'bench_bob').register()
    await alice.connect()
    await bob.connect()
    const conv = await alice.messenger.createConversation('direct', [bob.me.user.id])
    await bob.until(() => bob.messenger.conversations.length === 1)
    await alice.messenger.send(conv, 'warm-up')
    await bob.until(() => bob.texts(conv).length === 1)

    const endToEnd: Array<number> = []
    const clientEncrypt: Array<number> = []
    const serverConfirm: Array<number> = []
    for (let i = 0; i < 150; i++) {
      const before = bob.texts(conv).length
      // Resolved by the recipient's own state change, so no polling interval is included in the figure.
      const delivered = new Promise<number>((resolve) => {
        const stop = bob.messenger.subscribe(() => {
          if (bob.texts(conv).length <= before) return
          stop()
          resolve(performance.now())
        })
      })
      const start = performance.now()
      const sent = await alice.messenger.send(conv, `latency probe ${i}`)
      endToEnd.push((await delivered) - start)
      clientEncrypt.push(sent.encryptMs)
      serverConfirm.push(sent.totalMs)
    }
    // Baseline: the same relay hop with a ready-made envelope, i.e. no client-side cryptography in the timed section.
    const relayOnly: Array<number> = []
    for (let i = 0; i < 150; i++) {
      const s = alice.vault.sessions[bob.vault.keys.deviceId][0]
      const id = P.uuid()
      const created = Date.now()
      const e = P.ratchetEncrypt(s, { id, conv, from: alice.vault.keys.deviceId, to: bob.vault.keys.deviceId, created, expires: created + 60_000 }, P.encodePayload({ t: 'text', text: `relay probe ${i}` }))
      const message = { id, conv, created, expires: created + 60_000, envelopes: [{ to: e.to, header: e.header, pre: e.pre, nonce: e.nonce, ct: e.ct }] }
      const start = performance.now()
      await alice.transport.send!(message)
      relayOnly.push(performance.now() - start)
    }
    const e2e = stats(endToEnd)
    const relay = stats(relayOnly)
    const crypto = stats(clientEncrypt)
    results.end_to_end_ms = {
      'send → recipient has decrypted and stored (WebSocket, loopback)': e2e,
      'client: directory check + encrypt + persist, before the network': crypto,
      'send → server confirmation': stats(serverConfirm),
      'relay only: pre-built envelope → server confirmation (no client crypto)': relay,
      'cryptography share of p50 end-to-end latency': `${round((crypto.p50 / e2e.p50) * 100, 1)}%`,
    }
    expect(e2e.p50).toBeLessThan(250)
  } finally {
    await fixture.close()
  }

  mkdirSync('evidence', { recursive: true })
  writeFileSync('evidence/benchmark.json', `${JSON.stringify(results, null, 2)}\n`)
  console.log(JSON.stringify(results, null, 2))
})
