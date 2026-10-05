import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import WebSocket from 'ws';
import { createApp } from '../server/index.js';
import { totp } from '../server/security.js';
import { generateIdentity, publicIdentity, encryptMessage, decryptMessage } from '../public/crypto.js';

test('Threat-model integration: access control, ciphertext storage, replay, revocation and metadata', { timeout: 30000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'cipherroom-test-')), origin = 'http://127.0.0.1:3198';
  const app = createApp({ directory, origin }); app.server.listen(3198, '127.0.0.1'); await once(app.server, 'listening');
  t.after(async () => { await app.close(); rmSync(directory, { recursive: true, force: true }); });
  async function request(path, { method = 'GET', body, auth, headers = {} } = {}) {
    const response = await fetch(`${origin}/api${path}`, { method, headers: { Origin: origin, 'Content-Type': 'application/json', ...(auth ? { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0], headers: response.headers };
  }
  async function register(username) {
    const identity = await generateIdentity(); const registration = await request('/register', { method: 'POST', body: { username, password: 'Local-lab-password-123!' } }); assert.equal(registration.status, 200);
    const verified = await request('/auth/verify', { method: 'POST', body: { challenge: registration.body.challenge, code: totp(registration.body.secret), label: 'Test browser', ...publicIdentity(identity) } }); assert.equal(verified.status, 200);
    return { ...verified.body, cookie: verified.cookie, identity, secret: registration.body.secret };
  }
  const a = await register('alice'), b = await register('bob'), outsider = await register('mallory');
  assert.equal(a.user.role, 'admin'); assert.equal(b.user.role, 'member');
  assert.match(a.cookie, /^session=/);
  await t.test('secure headers, CSRF, unauthenticated access and least privilege', async () => {
    assert.equal((await request('/users')).status, 401);
    assert.equal((await request('/rooms', { method: 'POST', auth: a, body: {}, headers: { Origin: 'https://evil.invalid' } })).status, 403);
    assert.equal((await request('/rooms', { method: 'POST', auth: a, body: {}, headers: { 'X-CSRF-Token': 'wrong' } })).status, 403);
    assert.equal((await request('/admin/revoke', { method: 'POST', auth: b, body: { user: a.user.id } })).status, 403);
    const home = await fetch(origin); assert.match(home.headers.get('content-security-policy'), /frame-ancestors 'none'/); assert.equal(home.headers.get('cache-control'), 'no-store');
    const attempt = await request('/login', { method: 'POST', body: { username: "alice' OR '1'='1", password: 'invalid' } }); assert.equal(attempt.status, 401);
  });
  await t.test('MFA replay rejected and individual session termination enforced', async () => {
    const login = await request('/login', { method: 'POST', body: { username: 'alice', password: 'Local-lab-password-123!' } }); assert.equal(login.status, 200); assert.equal(login.cookie, undefined);
    const payload = { challenge: login.body.challenge, code: totp(a.secret), label: 'Test browser', ...publicIdentity(a.identity) };
    assert.equal((await request('/auth/verify', { method: 'POST', body: payload })).status, 401);
    const second = await request('/auth/verify', { method: 'POST', body: { ...payload, code: totp(a.secret, Math.floor(Date.now() / 30000) + 1) } }); assert.equal(second.status, 200);
    const secondary = { ...second.body, cookie: second.cookie };
    const sessions = (await request('/security', { auth: secondary })).body.sessions, id = sessions.find(s => s.current).id;
    assert.equal((await request('/sessions/revoke', { method: 'POST', auth: b, body: { session: id } })).status, 404);
    assert.equal((await request('/sessions/revoke', { method: 'POST', auth: a, body: { session: id } })).status, 200);
    assert.equal((await request('/me', { auth: secondary })).status, 401);
    assert.equal((await request('/me', { auth: a })).status, 200);
  });
  const created = await request('/rooms', { method: 'POST', auth: a, body: { name: 'Lab', kind: 'group', members: [b.user.id] } }); assert.equal(created.status, 200); const room = created.body.id;
  const devices = (await request(`/rooms/${room}/devices`, { auth: a })).body;
  const secretText = 'PLAINTEXT_MUST_NEVER_REACH_DATABASE_907213';
  const message = await encryptMessage(a.identity, room, devices, { text: secretText, file: { name: 'private-medical.txt', data: 'c2VjcmV0' } });
  const ws = new WebSocket(origin.replace('http', 'ws') + '/ws', { origin, headers: { Cookie: b.cookie } }); await once(ws, 'open');
  await t.test('WebSocket delivery, ciphertext-only storage and legitimate decryption', async () => {
    const delivery = new Promise(resolve => ws.on('message', raw => { const e = JSON.parse(raw); if (e.type === 'message') resolve(e); }));
    const start = performance.now(); const sent = await request(`/rooms/${room}/messages`, { method: 'POST', auth: a, body: message }); assert.equal(sent.status, 200);
    const received = await delivery; assert.equal(received.message.id, message.id);
    assert.equal((await decryptMessage(b.identity, received.message, devices.find(d => d.id === a.device))).text, secretText);
    const rows = app.db.prepare('SELECT * FROM messages').all(); assert(!JSON.stringify(rows).includes(secretText)); assert(!JSON.stringify(rows).includes('private-medical.txt'));
    assert(!JSON.stringify(app.db.prepare('SELECT * FROM audit').all()).includes(secretText));
    mkdirSync('evidence', { recursive: true }); writeFileSync('evidence/transport.json', JSON.stringify({ generatedAt: new Date().toISOString(), httpToWebSocketMs: performance.now() - start, scope: 'One loopback integration delivery, includes assertion/decryption time; not an internet latency benchmark', plaintextAbsentFromMessageRows: true, plaintextAbsentFromAuditRows: true }, null, 2));
  });
  await t.test('replay and signed-context tampering rejected', async () => {
    assert.equal((await request(`/rooms/${room}/messages`, { method: 'POST', auth: a, body: message })).status, 409);
    assert.equal((await request(`/rooms/${room}/messages`, { method: 'POST', auth: a, body: { ...message, id: crypto.randomUUID() } })).status, 400);
    assert.equal((await request(`/rooms/${room}/messages`, { method: 'POST', auth: b, body: message })).status, 400);
  });
  await t.test('unauthorized group access, stale step-up and revoked device', async () => {
    for (const endpoint of ['messages', 'devices', 'members']) assert.equal((await request(`/rooms/${room}/${endpoint}`, { auth: outsider })).status, 403);
    app.db.prepare('UPDATE sessions SET stepup=0 WHERE user_id=?').run(a.user.id);
    assert.equal((await request('/devices/revoke', { method: 'POST', auth: a, body: { device: a.device } })).status, 403);
    app.db.prepare('UPDATE sessions SET stepup=? WHERE user_id=?').run(Date.now(), a.user.id);
    const closed = once(ws, 'close'); assert.equal((await request('/devices/revoke', { method: 'POST', auth: b, body: { device: b.device } })).status, 200); assert.equal((await closed)[0], 4001);
    assert.equal((await request('/me', { auth: b })).status, 401);
    const oldTargets = await encryptMessage(a.identity, room, devices, { text: 'stale key set' }); assert.equal((await request(`/rooms/${room}/messages`, { method: 'POST', auth: a, body: oldTargets })).status, 409);
  });
  await t.test('membership removal and account containment', async () => {
    assert.equal((await request(`/rooms/${room}/members`, { method: 'DELETE', auth: a, body: { user: b.user.id } })).status, 200);
    assert.equal((await request('/admin/revoke', { method: 'POST', auth: a, body: { user: outsider.user.id } })).status, 200);
    assert.equal((await request('/me', { auth: outsider })).status, 401);
    const events = (await request('/security', { auth: a })).body.events;
    for (const kind of ['message.replay_blocked', 'message.integrity_failed', 'device.revoked', 'account.revoked']) assert(events.some(e => e.kind === kind));
  });
  await t.test('expired ciphertext is hidden and expired identifiers still cannot be replayed', async () => {
    app.db.prepare('UPDATE messages SET expires=0').run();
    assert.deepEqual((await request(`/rooms/${room}/messages`, { auth: a })).body, []);
    assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM replays WHERE id=?').get(message.id).n, 1);
  });
});
