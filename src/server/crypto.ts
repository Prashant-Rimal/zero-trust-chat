import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

export const random = (n = 32) => randomBytes(n).toString('base64url')
export const digest = (value: string) => createHash('sha256').update(value).digest('hex')

function scryptAsync(password: string, salt: string) {
  return new Promise<Buffer>((resolve, reject) =>
    scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) =>
      error ? reject(error) : resolve(key),
    ),
  )
}
export async function hashSecret(secret: string, salt = random(16)) {
  return `${salt}:${(await scryptAsync(secret, salt)).toString('hex')}`
}
export async function secretMatches(secret: string, stored: string) {
  const actual = await hashSecret(secret, stored.split(':')[0])
  return timingSafeEqual(Buffer.from(actual), Buffer.from(stored))
}

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32(bytes: Uint8Array) {
  let bits = 0
  let value = 0
  let result = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31]
  return result
}
function unbase32(input: string) {
  let bits = 0
  let value = 0
  const bytes: Array<number> = []
  for (const c of input) {
    value = (value << 5) | alphabet.indexOf(c)
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

/** RFC 6238, SHA-1, 6 digits, 30-second step. */
export function totp(secret: string, step = Math.floor(Date.now() / 30000)) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const mac = createHmac('sha1', unbase32(secret)).update(counter).digest()
  const offset = mac[19] & 15
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0')
}
/** Returns the accepted time step, or null. `lastStep` makes every code single-use. */
export function verifyTotp(secret: string, code: unknown, lastStep = -1, now = Date.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null
  const current = Math.floor(now / 30000)
  for (const step of [current, current - 1, current + 1]) {
    if (step > lastStep && timingSafeEqual(Buffer.from(totp(secret, step)), Buffer.from(code))) return step
  }
  return null
}
export const newTotpSecret = () => base32(randomBytes(20))

/** AES-256-GCM under the server secret, for data the server must be able to read back (TOTP seeds). */
export function sealAtRest(value: string, key: Buffer) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64')
}
export function unsealAtRest(value: string, key: Buffer) {
  const bytes = Buffer.from(value, 'base64')
  const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12))
  cipher.setAuthTag(bytes.subarray(12, 28))
  return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8')
}

/** Keyed, truncated hash: lets the server notice "same network as before" without storing the address. */
export const pseudonym = (value: string, key: Buffer) =>
  createHmac('sha256', key).update(value).digest('base64url').slice(0, 16)

/** Coarsens an address to its /24 (IPv4) or /48 (IPv6) before it is pseudonymised. */
export function networkOf(ip: string) {
  const v4 = ip.replace(/^::ffff:/, '').match(/^(\d+\.\d+\.\d+)\.\d+$/)
  if (v4) return v4[1]
  return ip.split(':').slice(0, 3).join(':')
}
