// Fixed field order is the wire format. Never sign arbitrary object serialization.
export function unsignedEnvelope(e) {
  return JSON.stringify({ v: e.v, id: e.id, room: e.room, sender: e.sender,
    created: e.created, expires: e.expires, ephemeral: e.ephemeral,
    iv: e.iv, ciphertext: e.ciphertext,
    keys: e.keys.map(k => ({ device: k.device, revision: k.revision, iv: k.iv, ciphertext: k.ciphertext })) });
}
export const messageContext = e => JSON.stringify([1, e.id, e.room, e.sender, e.created, e.expires]);
export const wrapContext = (e, k) => JSON.stringify([e.id, e.room, e.sender, k.device, k.revision]);
export const deviceCertificate = (device, revision, exchange) => JSON.stringify(['cipherroom-device-v1', device, revision, { kty: exchange.kty, crv: exchange.crv, x: exchange.x, y: exchange.y }]);
