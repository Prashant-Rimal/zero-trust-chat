import test from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, publicIdentity, encryptMessage, decryptMessage, fingerprint, createVault, saveVault, unlockVault, rotateExchange, verifyDevice } from '../public/crypto.js';
import { verifyTotp, totp } from '../server/security.js';
test('Authenticated encryption round-trip, tampering, impersonation and group exclusion', async () => {
  const a = await generateIdentity(), b = await generateIdentity(), outsider = await generateIdentity();
  const devices = [a, b].map(i => ({ id: i.device, ...publicIdentity(i), revision: 1 }));
  const message = { text: 'PROTECTED_CONTENT_8342', file: { name: 'secret.txt', data: 'c2VjcmV0' } };
  const envelope = await encryptMessage(a, 'room', devices, message);
  assert.deepEqual(await decryptMessage(b, envelope, devices[0]), message);
  assert(!JSON.stringify(envelope).includes(message.text)); assert(!JSON.stringify(envelope).includes('secret.txt'));
  await assert.rejects(decryptMessage(outsider, envelope, devices[0]), /no key/);
  for (const change of [{ ciphertext: 'AAAA' + envelope.ciphertext.slice(4) }, { room: 'other' }, { sender: b.device }, { expires: envelope.expires + 1 }]) await assert.rejects(decryptMessage(b, { ...envelope, ...change }, devices[0]), /Integrity/);
  await assert.rejects(decryptMessage(b, envelope, { signing: publicIdentity(outsider).signing }), /Integrity/);
  assert.notEqual(await fingerprint(devices[0].signing), await fingerprint(publicIdentity(outsider).signing));
  await assert.rejects(verifyDevice({ ...devices[0], exchange: publicIdentity(outsider).exchange }), /substitution/);
  await assert.rejects(verifyDevice({ ...devices[0], revision: 2 }), /substitution/);
  const rotated = await rotateExchange(b); await assert.rejects(decryptMessage(rotated, envelope, devices[0]), /no key/);
  const expired = { ...envelope, expires: Date.now() - 1 }; await assert.rejects(decryptMessage(b, expired, devices[0]), /expired/);
});
test('Local vault encryption rejects wrong passwords and modifications', async () => {
  const vault = await createVault('correct horse battery staple'), sealed = await saveVault(vault.identity, vault.key, vault.salt);
  assert(!JSON.stringify(sealed).includes(vault.identity.signing.d));
  assert.deepEqual((await unlockVault(sealed, 'correct horse battery staple')).identity, vault.identity);
  await assert.rejects(unlockVault(sealed, 'wrong password'));
  await assert.rejects(unlockVault({ ...sealed, ciphertext: 'AAAA' + sealed.ciphertext.slice(4) }, 'correct horse battery staple'));
});
test('TOTP RFC 6238 vector and one-time replay prevention', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totp(secret, 1), '287082');
  const step = Math.floor(Date.now() / 30000), code = totp(secret, step);
  assert.equal(verifyTotp(secret, code, step - 1), step); assert.equal(verifyTotp(secret, code, step), null);
});
