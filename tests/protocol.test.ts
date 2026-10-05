import { describe, expect, it } from 'vitest'
import * as P from '~/shared/protocol'

const ctx = (from: string, to: string, n = 0): P.EnvelopeContext => ({
  id: P.uuid(),
  conv: 'conv-1',
  from,
  to,
  created: 1_700_000_000_000 + n,
  expires: 1_700_000_600_000,
})
const pub = (k: P.DeviceKeys, userId = 'u'): P.PublicDevice => ({
  id: k.deviceId,
  userId,
  label: 'x',
  ik: k.ik.pub,
  dh: k.dh.pub,
  dhSig: k.dhSig,
  trust: 'trusted',
  xsig: null,
  created: 0,
})
const text = (s: string) => new TextEncoder().encode(s)
const str = (b: Uint8Array) => new TextDecoder().decode(b)

function pair(withOpk = true) {
  const a = P.generateDeviceKeys()
  const b = P.generateDeviceKeys()
  const [opk] = P.mintOneTimePrekeys(b, 1)
  const bundle: P.PrekeyBundle = { spk: P.publicSpk(b), opk: withOpk ? opk : null }
  const sa = P.initiateSession(a, pub(b), bundle)
  const first = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('hello'))
  const r = P.ratchetDecrypt(P.acceptSession(b, pub(a), first.pre!), first)
  expect(str(r.plaintext)).toBe('hello')
  return { a, b, sa, sb: r.session }
}

describe('X3DH + Double Ratchet', () => {
  it('establishes a session with and without a one-time prekey', () => {
    pair(true)
    pair(false)
  })

  it('consumes the one-time prekey so a recorded handshake cannot open a second session', () => {
    const a = P.generateDeviceKeys()
    const b = P.generateDeviceKeys()
    const [opk] = P.mintOneTimePrekeys(b, 1)
    const sa = P.initiateSession(a, pub(b), { spk: P.publicSpk(b), opk })
    const first = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('x'))
    P.acceptSession(b, pub(a), first.pre!)
    expect(() => P.acceptSession(b, pub(a), first.pre!)).toThrow(/already consumed/)
  })

  it('ratchets in both directions and stops sending the prekey header after a reply', () => {
    let { a, b, sa, sb } = pair()
    for (let i = 0; i < 20; i++) {
      const fromB = P.ratchetEncrypt(sb, ctx(b.deviceId, a.deviceId, i), text(`b${i}`))
      const ra = P.ratchetDecrypt(sa, fromB)
      sa = ra.session
      expect(str(ra.plaintext)).toBe(`b${i}`)
      const fromA = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId, i), text(`a${i}`))
      expect(fromA.pre).toBeNull()
      const rb = P.ratchetDecrypt(sb, fromA)
      sb = rb.session
      expect(str(rb.plaintext)).toBe(`a${i}`)
    }
  })

  it('handles out-of-order delivery through skipped message keys', () => {
    let { a, b, sa, sb } = pair()
    const msgs = [0, 1, 2, 3].map((i) => P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId, i), text(`m${i}`)))
    for (const i of [3, 1, 0, 2]) {
      const r = P.ratchetDecrypt(sb, msgs[i])
      sb = r.session
      expect(str(r.plaintext)).toBe(`m${i}`)
    }
    expect(Object.keys(sb.skipped)).toHaveLength(0)
  })

  it('rejects a replayed envelope and leaves state usable', () => {
    let { a, b, sa, sb } = pair()
    const m = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('once'))
    sb = P.ratchetDecrypt(sb, m).session
    expect(() => P.ratchetDecrypt(sb, m)).toThrow(P.ProtocolError)
    const next = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('again'))
    expect(str(P.ratchetDecrypt(sb, next).plaintext)).toBe('again')
  })

  it('rejects tampering with ciphertext, header or any envelope context field', () => {
    const { a, b, sa, sb } = pair()
    const m = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('integrity'))
    const flip = (s: string) => {
      const x = P.unb64(s)
      x[0] ^= 1
      return P.b64(x)
    }
    const mutations: Array<Partial<P.Envelope>> = [
      { ct: flip(m.ct) },
      { nonce: flip(m.nonce) },
      { conv: 'other-conv' },
      { from: 'other-device' },
      { to: 'other-device' },
      { id: P.uuid() },
      { created: m.created + 1 },
      { expires: m.expires + 1 },
      { header: { ...m.header, pn: m.header.pn + 1 } },
    ]
    for (const change of mutations) expect(() => P.ratchetDecrypt(sb, { ...m, ...change })).toThrow(P.ProtocolError)
    expect(str(P.ratchetDecrypt(sb, m).plaintext)).toBe('integrity')
  })

  it('gives forward secrecy: later state cannot decrypt earlier ciphertext', () => {
    let { a, b, sa, sb } = pair()
    const old = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('past secret'))
    sb = P.ratchetDecrypt(sb, old).session
    const reply = P.ratchetEncrypt(sb, ctx(b.deviceId, a.deviceId), text('r'))
    sa = P.ratchetDecrypt(sa, reply).session
    const m2 = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('n'))
    sb = P.ratchetDecrypt(sb, m2).session
    // An attacker who steals B's entire current state still cannot open the recorded envelope.
    expect(() => P.ratchetDecrypt(structuredClone(sb), old)).toThrow(P.ProtocolError)
  })

  it('heals after compromise: a stolen snapshot goes stale once the DH ratchet turns', () => {
    let { a, b, sa, sb } = pair()
    const stolen = structuredClone(sb)
    const r1 = P.ratchetEncrypt(sb, ctx(b.deviceId, a.deviceId), text('r1'))
    sa = P.ratchetDecrypt(sa, r1).session
    const m = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('after'))
    sb = P.ratchetDecrypt(sb, m).session
    const r2 = P.ratchetEncrypt(sb, ctx(b.deviceId, a.deviceId), text('r2'))
    sa = P.ratchetDecrypt(sa, r2).session
    const secret = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('post-compromise'))
    expect(() => P.ratchetDecrypt(stolen, secret)).toThrow(P.ProtocolError)
    expect(str(P.ratchetDecrypt(sb, secret).plaintext)).toBe('post-compromise')
  })

  it('bounds skipped keys to resist counter inflation', () => {
    const { a, b, sa, sb } = pair()
    const m = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('x'))
    expect(() => P.ratchetDecrypt(sb, { ...m, header: { ...m.header, n: 100_000 } })).toThrow(/Too many skipped/)
  })
})

describe('key substitution defences', () => {
  it('refuses a signed prekey not signed by the expected identity key', () => {
    const a = P.generateDeviceKeys()
    const b = P.generateDeviceKeys()
    const mallory = P.generateDeviceKeys(b.deviceId)
    expect(() => P.initiateSession(a, pub(b), { spk: P.publicSpk(mallory), opk: null })).toThrow(/signed prekey/)
  })

  it('refuses an identity DH key not signed by the identity key', () => {
    const a = P.generateDeviceKeys()
    const b = P.generateDeviceKeys()
    const mallory = P.generateDeviceKeys()
    expect(() => P.initiateSession(a, { ...pub(b), dh: mallory.dh.pub }, { spk: P.publicSpk(b), opk: null })).toThrow(
      /identity DH/,
    )
  })

  it('a responder handed a substituted sender identity derives different keys and fails closed', () => {
    const a = P.generateDeviceKeys()
    const b = P.generateDeviceKeys()
    const mallory = P.generateDeviceKeys(a.deviceId)
    const sa = P.initiateSession(a, pub(b), { spk: P.publicSpk(b), opk: null })
    const first = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('for b'))
    const sb = P.acceptSession(b, pub(mallory), first.pre!)
    expect(() => P.ratchetDecrypt(sb, first)).toThrow(P.ProtocolError)
  })

  it('binds cross-signatures and login proofs to their subject', () => {
    const old = P.generateDeviceKeys()
    const fresh = P.generateDeviceKeys()
    const other = P.generateDeviceKeys()
    const sig = P.crossSign(old, 'user-1', fresh.deviceId, fresh.ik.pub)
    expect(P.verifyCrossSign(old.ik.pub, 'user-1', fresh.deviceId, fresh.ik.pub, sig)).toBe(true)
    expect(P.verifyCrossSign(old.ik.pub, 'user-2', fresh.deviceId, fresh.ik.pub, sig)).toBe(false)
    expect(P.verifyCrossSign(old.ik.pub, 'user-1', fresh.deviceId, other.ik.pub, sig)).toBe(false)
    const proof = P.signLogin(old, 'challenge')
    expect(P.verifyLogin(old.ik.pub, 'challenge', old.deviceId, proof)).toBe(true)
    expect(P.verifyLogin(old.ik.pub, 'challenge-2', old.deviceId, proof)).toBe(false)
    expect(P.verifyLogin(other.ik.pub, 'challenge', old.deviceId, proof)).toBe(false)
  })
})

describe('rosters, fingerprints, padding, attachments, vault', () => {
  it('signs rosters canonically and detects any change', () => {
    const k = P.generateDeviceKeys()
    const signed = P.signRoster(k, { v: 1, conv: 'c', epoch: 1, kind: 'group', owner: 'u1', members: ['u2', 'u1', 'u2'] })
    expect(signed.roster.members).toEqual(['u1', 'u2'])
    expect(P.verifyRoster(signed, k.ik.pub)).toBe(true)
    expect(P.verifyRoster({ ...signed, roster: { ...signed.roster, members: ['u1', 'u2', 'ghost'] } }, k.ik.pub)).toBe(false)
    expect(P.verifyRoster({ ...signed, roster: { ...signed.roster, epoch: 2 } }, k.ik.pub)).toBe(false)
    expect(P.verifyRoster(signed, P.generateDeviceKeys().ik.pub)).toBe(false)
  })

  it('derives order-independent fingerprints that change when a device key is added', () => {
    const a = P.generateDeviceKeys().ik.pub
    const b = P.generateDeviceKeys().ik.pub
    const fp = P.userFingerprint('u1', [a, b])
    expect(fp).toMatch(/^\d{30}$/)
    expect(P.userFingerprint('u1', [b, a])).toBe(fp)
    expect(P.userFingerprint('u1', [a])).not.toBe(fp)
    expect(P.safetyNumber(fp, '0'.repeat(30))).toBe(P.safetyNumber('0'.repeat(30), fp))
  })

  it('pads plaintext into 256-byte buckets', () => {
    for (const n of [0, 1, 254, 255, 256, 1000]) {
      const padded = P.pad(new Uint8Array(n).fill(7))
      expect(padded.length % 256).toBe(0)
      expect(P.unpad(padded)).toHaveLength(n)
    }
    const { a, b, sa } = pair()
    const short = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('hi'))
    const longer = P.ratchetEncrypt(sa, ctx(a.deviceId, b.deviceId), text('a much longer sentence, still in one bucket'))
    expect(short.ct.length).toBe(longer.ct.length)
  })

  it('encrypts attachments and rejects modified ciphertext or the wrong conversation', () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 251)
    const enc = P.encryptAttachment('conv-1', bytes)
    expect(P.decryptAttachment('conv-1', enc, enc.ciphertext)).toEqual(bytes)
    const tampered = enc.ciphertext.slice()
    tampered[10] ^= 1
    expect(() => P.decryptAttachment('conv-1', enc, tampered)).toThrow(/digest/)
    expect(() => P.decryptAttachment('conv-2', enc, enc.ciphertext)).toThrow(/authentication/)
  })

  it('splits the password into unrelated auth and vault keys', async () => {
    const one = await P.deriveKeys('alice', 'correct horse battery', 1000)
    const again = await P.deriveKeys('alice', 'correct horse battery', 1000)
    const otherUser = await P.deriveKeys('bob', 'correct horse battery', 1000)
    expect(one.authKey).toBe(again.authKey)
    expect(one.authKey).not.toBe(otherUser.authKey)
    expect(one.authKey).not.toBe(P.b64(one.vaultKey))
    const sealed = P.seal(one.vaultKey, 'vault', text('secret'))
    expect(str(P.unseal(again.vaultKey, 'vault', sealed))).toBe('secret')
    expect(() => P.unseal(otherUser.vaultKey, 'vault', sealed)).toThrow()
    expect(() => P.unseal(one.vaultKey, 'other-label', sealed)).toThrow()
  })
})
