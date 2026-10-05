/**
 * Cipherroom protocol v2 — isomorphic (browser + Node) and synchronous.
 *
 * - Identity: Ed25519 signing key per device, X25519 identity DH key signed by it.
 * - Session setup: X3DH with signed prekeys and one-time prekeys.
 * - Messaging: Double Ratchet (DH ratchet + symmetric chains) per device pair.
 * - AEAD: XChaCha20-Poly1305, with the full envelope context as associated data.
 *
 * Nothing in this file talks to the network or to storage.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js'

export { randomBytes }

// ---------- encoding ----------

export function b64(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192))
  return btoa(out)
}
export function unb64(value: string): Uint8Array {
  const raw = atob(value)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}
const utf8 = utf8ToBytes
const fromUtf8 = (bytes: Uint8Array) => new TextDecoder('utf-8', { fatal: true }).decode(bytes)
export const uuid = () => crypto.randomUUID()

function equal(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

// ---------- types ----------

export type KeyPair = { priv: string; pub: string }
export type SignedPrekey = KeyPair & { id: number; sig: string; created: number }

/** Private key material for one device. Lives only inside the encrypted vault. */
export type DeviceKeys = {
  deviceId: string
  ik: KeyPair // Ed25519 identity (signing)
  dh: KeyPair // X25519 identity DH
  dhSig: string
  spk: SignedPrekey
  oldSpks: Array<SignedPrekey>
  opks: Record<string, KeyPair>
  nextOpkId: number
}

/** What the directory publishes for a device. */
export type PublicDevice = {
  id: string
  userId: string
  label: string
  ik: string
  dh: string
  dhSig: string
  trust: 'trusted' | 'revoked'
  xsig: { by: string; sig: string } | null
  created: number
}
export type PrekeyBundle = {
  spk: { id: number; pub: string; sig: string }
  opk: { id: number; pub: string } | null
}

export type RatchetHeader = { dh: string; pn: number; n: number }
export type PrekeyHeader = { ek: string; spk: number; opk: number | null }

export type Session = {
  rk: string
  dhs: KeyPair
  dhr: string | null
  cks: string | null
  ckr: string | null
  ns: number
  nr: number
  pn: number
  skipped: Record<string, string>
  ad: string
  /** Sent with every message until the peer answers, so they can run X3DH. */
  pre: PrekeyHeader | null
}

/** Per-recipient ciphertext as stored and relayed by the server. */
export type Envelope = {
  id: string
  conv: string
  from: string
  to: string
  created: number
  expires: number
  header: RatchetHeader
  pre: PrekeyHeader | null
  nonce: string
  ct: string
}
export type EnvelopeContext = Pick<Envelope, 'id' | 'conv' | 'from' | 'to' | 'created' | 'expires'>

export type Roster = {
  v: 1
  conv: string
  epoch: number
  kind: 'direct' | 'group'
  owner: string
  members: Array<string>
}
export type SignedRoster = { roster: Roster; signer: string; sig: string }

export class ProtocolError extends Error {
  constructor(
    message: string,
    public code:
      | 'bad-signature'
      | 'decrypt-failed'
      | 'replay'
      | 'key-substitution'
      | 'roster'
      | 'too-many-skipped'
      | 'no-prekey'
      | 'malformed',
  ) {
    super(message)
  }
}

// ---------- signatures over domain-separated strings ----------

const sign = (priv: string, message: string) => b64(ed25519.sign(utf8(message), unb64(priv)))
function verify(pub: string, message: string, sig: string) {
  try {
    return ed25519.verify(unb64(sig), utf8(message), unb64(pub))
  } catch {
    return false
  }
}

const dhCert = (deviceId: string, dh: string) => `cr/dh/v2|${deviceId}|${dh}`
const spkCert = (deviceId: string, id: number, pub: string) => `cr/spk/v2|${deviceId}|${id}|${pub}`
const crossCert = (userId: string, deviceId: string, ik: string) => `cr/xsign/v2|${userId}|${deviceId}|${ik}`
const loginProof = (challenge: string, deviceId: string) => `cr/login/v2|${challenge}|${deviceId}`
const rosterBytes = (r: Roster) =>
  `cr/roster/v2|${JSON.stringify([r.v, r.conv, r.epoch, r.kind, r.owner, [...r.members].sort()])}`

// ---------- key generation ----------

function x25519Pair(): KeyPair {
  const k = x25519.keygen()
  return { priv: b64(k.secretKey), pub: b64(k.publicKey) }
}

export function newSignedPrekey(deviceId: string, ikPriv: string, id: number, now = Date.now()): SignedPrekey {
  const pair = x25519Pair()
  return { ...pair, id, sig: sign(ikPriv, spkCert(deviceId, id, pair.pub)), created: now }
}

export function generateDeviceKeys(deviceId: string = uuid()): DeviceKeys {
  const signing = ed25519.keygen()
  const ik = { priv: b64(signing.secretKey), pub: b64(signing.publicKey) }
  const dh = x25519Pair()
  return {
    deviceId,
    ik,
    dh,
    dhSig: sign(ik.priv, dhCert(deviceId, dh.pub)),
    spk: newSignedPrekey(deviceId, ik.priv, 1),
    oldSpks: [],
    opks: {},
    nextOpkId: 1,
  }
}

/** Mints fresh one-time prekeys, records the private halves, returns the public halves to upload. */
export function mintOneTimePrekeys(keys: DeviceKeys, count: number) {
  const out: Array<{ id: number; pub: string }> = []
  for (let i = 0; i < count; i++) {
    const id = keys.nextOpkId++
    const pair = x25519Pair()
    keys.opks[id] = pair
    out.push({ id, pub: pair.pub })
  }
  return out
}

/** Session-key rotation: a new signed prekey. The previous one is kept briefly for in-flight handshakes. */
export function rotateSignedPrekey(keys: DeviceKeys, now = Date.now()) {
  keys.oldSpks = [keys.spk, ...keys.oldSpks].slice(0, 2)
  keys.spk = newSignedPrekey(keys.deviceId, keys.ik.priv, keys.spk.id + 1, now)
  return { id: keys.spk.id, pub: keys.spk.pub, sig: keys.spk.sig }
}

export const publicSpk = (keys: DeviceKeys) => ({ id: keys.spk.id, pub: keys.spk.pub, sig: keys.spk.sig })
export const signLogin = (keys: DeviceKeys, challenge: string) => sign(keys.ik.priv, loginProof(challenge, keys.deviceId))
export const verifyLogin = (ik: string, challenge: string, deviceId: string, sig: string) =>
  verify(ik, loginProof(challenge, deviceId), sig)
export const verifyDhCert = (d: { id: string; ik: string; dh: string; dhSig: string }) =>
  verify(d.ik, dhCert(d.id, d.dh), d.dhSig)
export const verifySpk = (deviceId: string, ik: string, spk: { id: number; pub: string; sig: string }) =>
  verify(ik, spkCert(deviceId, spk.id, spk.pub), spk.sig)

/** A trusted device vouches for a newly enrolled device of the same account. */
export const crossSign = (keys: DeviceKeys, userId: string, deviceId: string, ik: string) =>
  sign(keys.ik.priv, crossCert(userId, deviceId, ik))
export const verifyCrossSign = (approverIk: string, userId: string, deviceId: string, ik: string, sig: string) =>
  verify(approverIk, crossCert(userId, deviceId, ik), sig)

// ---------- rosters ----------

export function signRoster(keys: DeviceKeys, roster: Roster): SignedRoster {
  const clean = { ...roster, members: [...new Set(roster.members)].sort() }
  return { roster: clean, signer: keys.deviceId, sig: sign(keys.ik.priv, rosterBytes(clean)) }
}
export const verifyRoster = (signed: SignedRoster, signerIk: string) =>
  verify(signerIk, rosterBytes(signed.roster), signed.sig)

// ---------- fingerprints / safety numbers ----------

/** 30 decimal digits derived from a user's id and the full set of their device identity keys. */
export function userFingerprint(userId: string, identityKeys: Array<string>): string {
  let digest = sha256(utf8(`cr/fp/v2|${userId}|${[...identityKeys].sort().join(',')}`))
  // Iterated hashing makes brute-forcing a colliding key set more expensive.
  for (let i = 0; i < 5200; i++) digest = sha256(digest)
  let out = ''
  for (let i = 0; i < 6; i++) {
    const chunk = digest.subarray(i * 5, i * 5 + 5)
    let value = 0n
    for (const byte of chunk) value = (value << 8n) | BigInt(byte)
    out += (value % 100000n).toString().padStart(5, '0')
  }
  return out
}
export function safetyNumber(a: string, b: string) {
  const joined = a < b ? a + b : b + a
  return joined.match(/.{5}/g)!.join(' ')
}
export function deviceFingerprint(ik: string) {
  const digest = sha256(concatBytes(utf8('cr/devfp/v2|'), unb64(ik)))
  return [...digest.subarray(0, 8)].map((v) => v.toString(16).padStart(2, '0')).join('').match(/.{4}/g)!.join(' ')
}

// ---------- X3DH ----------

const dh = (priv: string, pub: string) => x25519.getSharedSecret(unb64(priv), unb64(pub))

function x3dhSecret(parts: Array<Uint8Array>) {
  const ikm = concatBytes(new Uint8Array(32).fill(0xff), ...parts)
  const secret = hkdf(sha256, ikm, new Uint8Array(32), utf8('cr/x3dh/v2'), 32)
  for (const part of parts) part.fill(0)
  return secret
}

// Binding both Ed25519 identities and device ids means a swapped directory entry yields a different AD.
const associatedData = (initIk: string, initDevice: string, respIk: string, respDevice: string) =>
  b64(sha256(utf8(`cr/ad/v2|${initIk}|${initDevice}|${respIk}|${respDevice}`)))

function kdfRoot(rk: string, dhOut: Uint8Array) {
  const out = hkdf(sha256, dhOut, unb64(rk), utf8('cr/rk/v2'), 64)
  dhOut.fill(0)
  return { rk: b64(out.subarray(0, 32)), ck: b64(out.subarray(32)) }
}
function kdfChain(ck: string) {
  const key = unb64(ck)
  return { mk: hmac(sha256, key, Uint8Array.of(1)), ck: b64(hmac(sha256, key, Uint8Array.of(2))) }
}

/** Initiator side. `peer` and `bundle` must already be verified with {@link verifyDhCert} / {@link verifySpk}. */
export function initiateSession(keys: DeviceKeys, peer: Pick<PublicDevice, 'id' | 'ik' | 'dh' | 'dhSig'>, bundle: PrekeyBundle): Session {
  if (!verifyDhCert(peer)) throw new ProtocolError('Peer identity DH key is not signed by its identity key.', 'bad-signature')
  if (!verifySpk(peer.id, peer.ik, bundle.spk)) throw new ProtocolError('Peer signed prekey has an invalid signature.', 'bad-signature')
  const ek = x25519Pair()
  const parts = [dh(keys.dh.priv, bundle.spk.pub), dh(ek.priv, peer.dh), dh(ek.priv, bundle.spk.pub)]
  if (bundle.opk) parts.push(dh(ek.priv, bundle.opk.pub))
  const sk = x3dhSecret(parts)
  const dhs = x25519Pair()
  const root = kdfRoot(b64(sk), dh(dhs.priv, bundle.spk.pub))
  return {
    rk: root.rk,
    dhs,
    dhr: bundle.spk.pub,
    cks: root.ck,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    ad: associatedData(keys.ik.pub, keys.deviceId, peer.ik, peer.id),
    pre: { ek: ek.pub, spk: bundle.spk.id, opk: bundle.opk?.id ?? null },
  }
}

/** Responder side. Consumes (deletes) the one-time prekey named by the header. */
export function acceptSession(keys: DeviceKeys, peer: Pick<PublicDevice, 'id' | 'ik' | 'dh' | 'dhSig'>, pre: PrekeyHeader): Session {
  if (!verifyDhCert(peer)) throw new ProtocolError('Sender identity DH key is not signed by its identity key.', 'bad-signature')
  const spk = [keys.spk, ...keys.oldSpks].find((k) => k.id === pre.spk)
  if (!spk) throw new ProtocolError('Handshake used a signed prekey this device no longer holds.', 'no-prekey')
  const parts = [dh(spk.priv, peer.dh), dh(keys.dh.priv, pre.ek), dh(spk.priv, pre.ek)]
  if (pre.opk !== null) {
    const opk = keys.opks[pre.opk]
    if (!opk) throw new ProtocolError('Handshake used a one-time prekey that was already consumed.', 'no-prekey')
    parts.push(dh(opk.priv, pre.ek))
    delete keys.opks[pre.opk]
  }
  const sk = x3dhSecret(parts)
  return {
    rk: b64(sk),
    dhs: { priv: spk.priv, pub: spk.pub },
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    ad: associatedData(peer.ik, peer.id, keys.ik.pub, keys.deviceId),
    pre: null,
  }
}

// ---------- Double Ratchet ----------

const MAX_SKIP = 500
const MAX_STORED_SKIPPED = 1000

const aad = (ad: string, ctx: EnvelopeContext, h: RatchetHeader) =>
  utf8(JSON.stringify(['cr/msg/v2', ad, ctx.id, ctx.conv, ctx.from, ctx.to, ctx.created, ctx.expires, h.dh, h.pn, h.n]))

const cipherKey = (mk: Uint8Array) => hkdf(sha256, mk, undefined, utf8('cr/mk/v2'), 32)

/** Pads to a 256-byte bucket so ciphertext length only reveals a coarse size class. */
export function pad(bytes: Uint8Array, bucket = 256) {
  const out = new Uint8Array(Math.ceil((bytes.length + 1) / bucket) * bucket)
  out.set(bytes)
  out[bytes.length] = 0x80
  return out
}
export function unpad(bytes: Uint8Array) {
  let end = bytes.length - 1
  while (end >= 0 && bytes[end] === 0) end--
  if (end < 0 || bytes[end] !== 0x80) throw new ProtocolError('Invalid padding.', 'malformed')
  return bytes.subarray(0, end)
}

/** Mutates `session` (advances the sending chain). */
export function ratchetEncrypt(session: Session, ctx: EnvelopeContext, plaintext: Uint8Array): Envelope {
  if (!session.cks) throw new ProtocolError('Session has no sending chain yet.', 'malformed')
  const step = kdfChain(session.cks)
  session.cks = step.ck
  const header = { dh: session.dhs.pub, pn: session.pn, n: session.ns++ }
  const nonce = randomBytes(24)
  const key = cipherKey(step.mk)
  const ct = xchacha20poly1305(key, nonce, aad(session.ad, ctx, header)).encrypt(pad(plaintext))
  step.mk.fill(0)
  key.fill(0)
  return { ...ctx, header, pre: session.pre, nonce: b64(nonce), ct: b64(ct) }
}

function skip(session: Session, until: number) {
  if (!session.ckr) return
  if (until - session.nr > MAX_SKIP) throw new ProtocolError('Too many skipped messages.', 'too-many-skipped')
  while (session.nr < until) {
    const step = kdfChain(session.ckr)
    session.ckr = step.ck
    session.skipped[`${session.dhr}|${session.nr++}`] = b64(step.mk)
  }
  const stored = Object.keys(session.skipped)
  for (const key of stored.slice(0, Math.max(0, stored.length - MAX_STORED_SKIPPED))) delete session.skipped[key]
}

function open(mk: Uint8Array, session: Session, e: Envelope) {
  const key = cipherKey(mk)
  try {
    return unpad(xchacha20poly1305(key, unb64(e.nonce), aad(session.ad, e, e.header)).decrypt(unb64(e.ct)))
  } catch {
    throw new ProtocolError('Message failed authentication.', 'decrypt-failed')
  } finally {
    key.fill(0)
    mk.fill(0)
  }
}

/**
 * Returns the plaintext and the advanced session. The input session is never mutated, so a
 * forged or replayed envelope cannot corrupt ratchet state.
 */
export function ratchetDecrypt(input: Session, e: Envelope): { session: Session; plaintext: Uint8Array } {
  const session: Session = structuredClone(input)
  const h = e.header
  const skippedKey = `${h.dh}|${h.n}`
  if (session.skipped[skippedKey]) {
    const plaintext = open(unb64(session.skipped[skippedKey]), session, e)
    delete session.skipped[skippedKey]
    return { session, plaintext }
  }
  if (h.dh !== session.dhr) {
    skip(session, h.pn)
    session.pn = session.ns
    session.ns = 0
    session.nr = 0
    session.dhr = h.dh
    const recv = kdfRoot(session.rk, dh(session.dhs.priv, h.dh))
    session.ckr = recv.ck
    session.dhs = x25519Pair()
    const send = kdfRoot(recv.rk, dh(session.dhs.priv, h.dh))
    session.rk = send.rk
    session.cks = send.ck
  } else if (h.n < session.nr) {
    // The key for this counter was already used and deleted: a replay.
    throw new ProtocolError('Message key already consumed.', 'replay')
  }
  skip(session, h.n)
  const step = kdfChain(session.ckr!)
  session.ckr = step.ck
  session.nr++
  const plaintext = open(step.mk, session, e)
  // The peer has demonstrably completed the handshake; stop attaching the prekey header.
  session.pre = null
  return { session, plaintext }
}

// ---------- payloads and attachments ----------

export type FileRef = { id: string; key: string; nonce: string; name: string; type: string; size: number; digest: string }
export type Payload =
  | { t: 'text'; text: string; file?: FileRef }
  | { t: 'meta'; name: string }

export const encodePayload = (payload: Payload) => utf8(JSON.stringify(payload))
export function decodePayload(bytes: Uint8Array): Payload {
  try {
    const value = JSON.parse(fromUtf8(bytes))
    if (value?.t === 'text' && typeof value.text === 'string') return value
    if (value?.t === 'meta' && typeof value.name === 'string') return value
  } catch {
    // fall through
  }
  throw new ProtocolError('Unrecognised payload.', 'malformed')
}

const fileAad = (conv: string) => utf8(`cr/file/v2|${conv}`)

export function encryptAttachment(conv: string, bytes: Uint8Array) {
  const key = randomBytes(32)
  const nonce = randomBytes(24)
  const ciphertext = xchacha20poly1305(key, nonce, fileAad(conv)).encrypt(bytes)
  return { ciphertext, key: b64(key), nonce: b64(nonce), digest: b64(sha256(ciphertext)) }
}
export function decryptAttachment(conv: string, ref: Pick<FileRef, 'key' | 'nonce' | 'digest'>, ciphertext: Uint8Array) {
  if (!equal(sha256(ciphertext), unb64(ref.digest))) throw new ProtocolError('Attachment digest mismatch.', 'decrypt-failed')
  try {
    return xchacha20poly1305(unb64(ref.key), unb64(ref.nonce), fileAad(conv)).decrypt(ciphertext)
  } catch {
    throw new ProtocolError('Attachment failed authentication.', 'decrypt-failed')
  }
}

// ---------- vault sealing (local storage at rest) ----------

export function seal(key: Uint8Array, label: string, bytes: Uint8Array) {
  const nonce = randomBytes(24)
  return { v: 2, nonce: b64(nonce), ct: b64(xchacha20poly1305(key, nonce, utf8(label)).encrypt(bytes)) }
}
export function unseal(key: Uint8Array, label: string, sealed: { nonce: string; ct: string }) {
  return xchacha20poly1305(key, unb64(sealed.nonce), utf8(label)).decrypt(unb64(sealed.ct))
}

/**
 * Splits the password into an authentication key (sent to the server) and a vault key (never
 * leaves the device). The server cannot derive the vault key from what it receives.
 */
export async function deriveKeys(username: string, password: string, iterations = 600_000) {
  const material = await crypto.subtle.importKey('raw', utf8(password.normalize('NFKC')) as BufferSource, 'PBKDF2', false, ['deriveBits'])
  const salt = sha256(utf8(`cr/kdf/v2|${username}`))
  const master = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations }, material, 256))
  const authKey = b64(hkdf(sha256, master, undefined, utf8('cr/auth/v2'), 32))
  const vaultKey = hkdf(sha256, master, undefined, utf8('cr/vault/v2'), 32)
  master.fill(0)
  return { authKey, vaultKey }
}
