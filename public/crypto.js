import { unsignedEnvelope, messageContext, wrapContext, deviceCertificate } from '../shared/protocol.js';
const subtle = globalThis.crypto.subtle, encoder = new TextEncoder(), decoder = new TextDecoder();
export const encode = value => encoder.encode(value);
export function base64(value) {
  const bytes = new Uint8Array(value); let result = '';
  for (let i = 0; i < bytes.length; i += 8192) result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(result);
}
export const unbase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const nonce = () => crypto.getRandomValues(new Uint8Array(12));
const clean = key => ({ kty: key.kty, crv: key.crv, x: key.x, y: key.y });
export async function generateIdentity() {
  const signing = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const exchange = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return certify({ device: crypto.randomUUID(), signing: await subtle.exportKey('jwk', signing.privateKey), exchange: await subtle.exportKey('jwk', exchange.privateKey), revision: 1, pins: {} });
}
async function certify(identity) {
  const signing = await subtle.importKey('jwk', identity.signing, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  identity.certificate = base64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signing, encode(deviceCertificate(identity.device, identity.revision, identity.exchange))));
  return identity;
}
export function publicIdentity(identity) { return { device: identity.device, signing: clean(identity.signing), exchange: clean(identity.exchange), certificate: identity.certificate }; }
export async function verifyDevice(device) {
  const key = await subtle.importKey('jwk', device.signing, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (!await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unbase64(device.certificate), encode(deviceCertificate(device.id, device.revision, device.exchange)))) throw new Error('Device exchange key signature invalid. Key substitution blocked.');
}
export async function fingerprint(key) {
  const hash = await subtle.digest('SHA-256', encode(JSON.stringify(clean(key))));
  return [...new Uint8Array(hash)].map(v => v.toString(16).padStart(2, '0')).join('').match(/.{4}/g).join(' ');
}
export async function deriveVaultKey(password, salt) {
  const input = await subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: unbase64(salt) }, input, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function saveVault(identity, key, salt) {
  const iv = nonce(), ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encode('cipherroom-vault-v1') }, key, encode(JSON.stringify(identity)));
  return { v: 1, salt, iv: base64(iv), ciphertext: base64(ciphertext) };
}
export async function unlockVault(vault, password) {
  const key = await deriveVaultKey(password, vault.salt);
  const clear = await subtle.decrypt({ name: 'AES-GCM', iv: unbase64(vault.iv), additionalData: encode('cipherroom-vault-v1') }, key, unbase64(vault.ciphertext));
  return { identity: JSON.parse(decoder.decode(clear)), key, salt: vault.salt };
}
export async function createVault(password) {
  const salt = base64(crypto.getRandomValues(new Uint8Array(16))), key = await deriveVaultKey(password, salt);
  return { identity: await generateIdentity(), key, salt };
}
async function wrappingKey(privateJwk, publicJwk, context, usage) {
  const privateKey = await subtle.importKey('jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const publicKey = await subtle.importKey('jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  new Uint8Array(shared).fill(0);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encode('cipherroom-wrap-v1'), info: encode(context) }, material, { name: 'AES-GCM', length: 256 }, false, [usage]);
}
export async function encryptMessage(identity, room, devices, payload, lifetime = 86400) {
  const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephemeralPrivate = await subtle.exportKey('jwk', ephemeral.privateKey);
  const e = { v: 1, id: crypto.randomUUID(), room, sender: identity.device, created: Date.now(), expires: Date.now() + lifetime * 1000,
    ephemeral: clean(await subtle.exportKey('jwk', ephemeral.publicKey)), iv: base64(nonce()), keys: [] };
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const contentKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  e.ciphertext = base64(await subtle.encrypt({ name: 'AES-GCM', iv: unbase64(e.iv), additionalData: encode(messageContext(e)) }, contentKey, encode(JSON.stringify(payload))));
  for (const device of devices) {
    await verifyDevice(device);
    const k = { device: device.id, revision: device.revision, iv: base64(nonce()) }, context = wrapContext(e, k);
    const key = await wrappingKey(ephemeralPrivate, device.exchange, context, 'encrypt');
    k.ciphertext = base64(await subtle.encrypt({ name: 'AES-GCM', iv: unbase64(k.iv), additionalData: encode(context) }, key, raw)); e.keys.push(k);
  }
  raw.fill(0);
  const signingKey = await subtle.importKey('jwk', identity.signing, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  e.signature = base64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, encode(unsignedEnvelope(e))));
  return e;
}
export async function decryptMessage(identity, e, sender) {
  if (e.v !== 1 || e.expires <= Date.now()) throw new Error('Message expired.');
  const publicKey = await subtle.importKey('jwk', sender.signing, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (!await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, unbase64(e.signature), encode(unsignedEnvelope(e)))) throw new Error('Integrity verification failed.');
  const k = e.keys.find(k => k.device === identity.device && k.revision === identity.revision);
  if (!k) throw new Error('This device has no key for this message.');
  const context = wrapContext(e, k), wrapKey = await wrappingKey(identity.exchange, e.ephemeral, context, 'decrypt');
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv: unbase64(k.iv), additionalData: encode(context) }, wrapKey, unbase64(k.ciphertext));
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']); new Uint8Array(raw).fill(0);
  return JSON.parse(decoder.decode(await subtle.decrypt({ name: 'AES-GCM', iv: unbase64(e.iv), additionalData: encode(messageContext(e)) }, key, unbase64(e.ciphertext))));
}
export async function rotateExchange(identity) {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return certify({ ...identity, exchange: await subtle.exportKey('jwk', pair.privateKey), revision: identity.revision + 1 });
}
