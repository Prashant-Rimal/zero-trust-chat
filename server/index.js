import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify } from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { openStore } from './store.js';
import { random, digest, hashPassword, passwordMatches, newTotpSecret, verifyTotp, seal, unseal } from './security.js';
import { unsignedEnvelope, deviceCertificate } from '../shared/protocol.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const HOUR = 3600000;
export function createApp({ directory = process.env.DATA_DIR || resolve(ROOT, 'data'), origin = process.env.APP_ORIGIN || 'http://127.0.0.1:3000', secure = process.env.COOKIE_SECURE === '1' } = {}) {
  const { db, master } = openStore(directory);
  const clients = new Set(), limits = new Map(), challenges = new Map();
  const one = (sql, ...args) => db.prepare(sql).get(...args);
  const all = (sql, ...args) => db.prepare(sql).all(...args);
  const run = (sql, ...args) => db.prepare(sql).run(...args);
  const audit = (user, kind, severity = 'info', detail = '') => run('INSERT INTO audit(user_id,kind,severity,detail,created) VALUES(?,?,?,?,?)', user || null, kind, severity, detail, Date.now());
  const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
  function rate(key, max = 15, period = 60000) {
    const now = Date.now(), entry = limits.get(key);
    const next = !entry || now > entry.until ? { count: 0, until: now + period } : entry;
    next.count++; limits.set(key, next);
    if (next.count > max) fail(429, 'Too many attempts. Try again later.');
  }
  function session(req) {
    const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('session='))?.slice(8);
    if (!token) fail(401, 'Sign in to continue.');
    const s = one(`SELECT s.*,u.username,u.role,u.revoked AS account_revoked,d.trusted FROM sessions s
      JOIN users u ON u.id=s.user_id JOIN devices d ON d.id=s.device_id WHERE s.hash=?`, digest(token));
    if (!s || s.revoked || s.account_revoked || !s.trusted || s.expires < Date.now() || s.seen < Date.now() - 30 * 60000) fail(401, 'Session expired or revoked.');
    return s;
  }
  function fresh(s) { if (s.stepup < Date.now() - 5 * 60000) fail(403, 'Fresh verification required. Use Verify identity first.'); }
  function member(room, user) {
    if (!one('SELECT 1 FROM members WHERE room_id=? AND user_id=?', room, user)) fail(403, 'Channel access denied.');
  }
  function devices(room) {
    return all(`SELECT d.id,d.user_id,u.username,d.label,d.signing,d.exchange,d.certificate,d.revision FROM devices d
      JOIN members m ON m.user_id=d.user_id JOIN users u ON u.id=d.user_id
      WHERE m.room_id=? AND d.trusted=1 AND u.revoked=0 ORDER BY d.id`, room)
      .map(d => ({ ...d, signing: JSON.parse(d.signing), exchange: JSON.parse(d.exchange) }));
  }
  function notify(room, event) {
    for (const c of clients) {
      try { const s = session(c.req); member(room, s.user_id); c.ws.send(JSON.stringify(event)); }
      catch (e) { if (e.status === 401) c.ws.close(4001, 'Session revoked'); }
    }
  }
  function disconnectInvalid() {
    for (const c of clients) { try { session(c.req); } catch { c.ws.close(4001, 'Session revoked'); } }
  }
  function publicKey(value) {
    if (!value || value.kty !== 'EC' || value.crv !== 'P-256' || typeof value.x !== 'string' || typeof value.y !== 'string' || value.d) fail(400, 'Invalid public key.');
    const clean = { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
    try { createPublicKey({ key: clean, format: 'jwk' }); } catch { fail(400, 'Invalid public key.'); }
    return clean;
  }
  function checkCertificate(device, revision, exchange, signing, certificate) {
    if (typeof certificate !== 'string' || certificate.length !== 88 || !verify('sha256', Buffer.from(deviceCertificate(device, revision, exchange)), { key: createPublicKey({ key: signing, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(certificate, 'base64'))) fail(400, 'Invalid device key certificate.');
  }
  const str = (v, max = 100) => { if (typeof v !== 'string' || !v.trim() || v.length > max) fail(400, 'Invalid input.'); return v.trim(); };
  const uuid = v => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(v);
  const b64 = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(v);
  async function body(req) {
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; if (size > 3200000) fail(413, 'Attachment exceeds the encrypted upload limit.'); chunks.push(chunk); }
    try { return JSON.parse(Buffer.concat(chunks).toString()); } catch { fail(400, 'Invalid JSON.'); }
  }
  function useTotp(user, code) {
    const step = verifyTotp(unseal(user.totp, master), code, user.last_totp);
    if (step === null) { audit(user.id, 'mfa.failed', 'warning'); fail(401, 'Invalid or already used authenticator code. Wait for a new code.'); }
    run('UPDATE users SET last_totp=? WHERE id=?', step, user.id);
  }
  function setSession(res, user, device) {
    const token = random(), csrf = random(), now = Date.now();
    run('INSERT INTO sessions(hash,user_id,device_id,csrf,created,expires,seen,stepup) VALUES(?,?,?,?,?,?,?,?)', digest(token), user.id, device, csrf, now, now + 8 * HOUR, now, now);
    res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure ? '; Secure' : ''}`);
    audit(user.id, 'session.started', 'info', device);
    return { user: { id: user.id, username: user.username, role: user.role }, device, csrf };
  }
  async function api(req, res, path) {
    const method = req.method;
    if (method !== 'GET' && req.headers.origin !== origin) fail(403, 'Origin check failed.');
    const b = method === 'GET' ? {} : await body(req);
    if (path === '/api/register' && method === 'POST') {
      rate(`register:${req.socket.remoteAddress}`, 5, HOUR);
      const username = str(b.username, 24).toLowerCase();
      if (!/^[a-z][a-z0-9_.-]{2,23}$/.test(username)) fail(400, 'Use 3–24 lowercase letters, numbers, dots or underscores.');
      if (typeof b.password !== 'string' || b.password.length < 12 || b.password.length > 128) fail(400, 'Use a password between 12 and 128 characters.');
      if (one('SELECT 1 FROM users WHERE username=?', username)) fail(409, 'Username unavailable.');
      const hash = await hashPassword(b.password), secret = newTotpSecret(), id = random(16), challenge = random();
      if (one('SELECT 1 FROM users WHERE username=?', username)) fail(409, 'Username unavailable.');
      run('INSERT INTO users(id,username,password,role,totp,created) VALUES(?,?,?,?,?,?)', id, username, hash, 'member', seal(secret, master), Date.now());
      challenges.set(digest(challenge), { user: id, enroll: true, until: Date.now() + 10 * 60000 });
      return { challenge, secret, uri: `otpauth://totp/Cipherroom:${username}?secret=${secret}&issuer=Cipherroom&algorithm=SHA1&digits=6&period=30` };
    }
    if (path === '/api/login' && method === 'POST') {
      const username = str(b.username, 24).toLowerCase();
      rate(`login-ip:${req.socket.remoteAddress}`, 30, 5 * 60000); rate(`login:${username}`, 10, 5 * 60000);
      const u = one('SELECT * FROM users WHERE username=?', username);
      if (typeof b.password !== 'string' || b.password.length > 128) fail(400, 'Invalid credentials.');
      const valid = u ? await passwordMatches(b.password, u.password) : (await hashPassword(b.password), false);
      if (!valid || !u.active || u.revoked) { audit(u?.id, 'login.failed', 'warning'); fail(401, 'Invalid credentials or account unavailable.'); }
      const challenge = random(); challenges.set(digest(challenge), { user: u.id, enroll: false, until: Date.now() + 5 * 60000 });
      return { challenge };
    }
    if (path === '/api/auth/verify' && method === 'POST') {
      rate(`mfa:${req.socket.remoteAddress}`, 20, 5 * 60000);
      const ch = challenges.get(digest(String(b.challenge)));
      if (!ch || ch.until < Date.now()) fail(401, 'Sign-in challenge expired.');
      const u = one('SELECT * FROM users WHERE id=?', ch.user);
      if (u.revoked) fail(401, 'Account revoked.');
      const signing = publicKey(b.signing), exchange = publicKey(b.exchange);
      if (!uuid(b.device)) fail(400, 'Invalid device.');
      const label = str(b.label, 48);
      let d = one('SELECT * FROM devices WHERE id=?', b.device);
      if (d && (d.user_id !== u.id || !d.trusted || d.signing !== JSON.stringify(signing) || d.exchange !== JSON.stringify(exchange))) fail(403, 'Device is revoked or its identity changed.');
      checkCertificate(b.device, d?.revision || 1, exchange, signing, b.certificate);
      useTotp(u, b.code);
      challenges.delete(digest(String(b.challenge)));
      if (ch.enroll) {
        // Admin bootstrapping occurs only after the first successfully enrolled MFA identity.
        const role = one("SELECT 1 FROM users WHERE role='admin' AND active=1") ? 'member' : 'admin';
        run('UPDATE users SET active=1,role=? WHERE id=?', role, u.id); u.role = role;
      }
      if (!d) {
        run('INSERT INTO devices(id,user_id,label,signing,exchange,certificate,created) VALUES(?,?,?,?,?,?,?)', b.device, u.id, label, JSON.stringify(signing), JSON.stringify(exchange), b.certificate, Date.now());
        audit(u.id, 'device.enrolled', 'warning', b.device);
      }
      return setSession(res, u, b.device);
    }
    const s = session(req);
    if (method !== 'GET' && req.headers['x-csrf-token'] !== s.csrf) fail(403, 'CSRF check failed.');
    run('UPDATE sessions SET seen=? WHERE hash=?', Date.now(), s.hash);
    rate(`session:${s.hash}`, 180);
    if (path === '/api/me' && method === 'GET') return { user: { id: s.user_id, username: s.username, role: s.role }, device: s.device_id, csrf: s.csrf };
    if (path === '/api/logout' && method === 'POST') {
      run('UPDATE sessions SET revoked=1 WHERE hash=?', s.hash); disconnectInvalid();
      res.setHeader('Set-Cookie', `session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`); return { ok: true };
    }
    if (path === '/api/stepup' && method === 'POST') {
      rate(`stepup:${s.user_id}`, 6, 5 * 60000); useTotp(one('SELECT * FROM users WHERE id=?', s.user_id), b.code);
      run('UPDATE sessions SET stepup=? WHERE hash=?', Date.now(), s.hash); audit(s.user_id, 'session.stepup'); return { ok: true };
    }
    if (path === '/api/users' && method === 'GET') return all('SELECT id,username,role FROM users WHERE active=1 AND revoked=0 ORDER BY username');
    if (path === '/api/rooms' && method === 'GET') return all(`SELECT r.*,(SELECT COUNT(*) FROM members WHERE room_id=r.id) AS member_count,
      (SELECT MAX(created) FROM messages WHERE room_id=r.id) AS last_activity FROM rooms r JOIN members m ON m.room_id=r.id WHERE m.user_id=? ORDER BY r.created DESC`, s.user_id);
    if (path === '/api/rooms' && method === 'POST') {
      fresh(s); const name = str(b.name, 60), kind = b.kind;
      if (!['direct', 'group'].includes(kind) || !Array.isArray(b.members) || b.members.length > 20) fail(400, 'Invalid channel.');
      const members = [...new Set([s.user_id, ...b.members])];
      if (members.length < 2 || (kind === 'direct' && members.length !== 2)) fail(400, 'Select channel participants.');
      for (const id of members) if (typeof id !== 'string' || !one('SELECT 1 FROM users WHERE id=? AND active=1 AND revoked=0', id)) fail(400, 'Participant unavailable.');
      const id = random(16); run('INSERT INTO rooms VALUES(?,?,?,?,?)', id, name, kind, s.user_id, Date.now());
      for (const user of members) run('INSERT INTO members VALUES(?,?)', id, user);
      audit(s.user_id, 'channel.created'); notify(id, { type: 'rooms' }); return { id };
    }
    const roomRoute = path.match(/^\/api\/rooms\/([\w-]+)\/(devices|messages|members)$/);
    if (roomRoute) {
      const [, room, action] = roomRoute; member(room, s.user_id);
      if (action === 'devices' && method === 'GET') return devices(room);
      if (action === 'members' && method === 'GET') return all('SELECT u.id,u.username FROM users u JOIN members m ON m.user_id=u.id WHERE m.room_id=?', room);
      if (action === 'members' && method === 'DELETE') {
        fresh(s); if (!one('SELECT 1 FROM rooms WHERE id=? AND owner=?', room, s.user_id) || b.user === s.user_id) fail(403, 'Only the channel owner can remove another member.');
        run('DELETE FROM members WHERE room_id=? AND user_id=?', room, str(b.user)); audit(s.user_id, 'channel.member_removed', 'warning');
        notify(room, { type: 'members', room }); return { ok: true };
      }
      if (action === 'messages' && method === 'GET') return all('SELECT envelope FROM messages WHERE room_id=? AND expires>? ORDER BY created DESC LIMIT 100', room, Date.now()).reverse().map(r => JSON.parse(r.envelope));
      if (action === 'messages' && method === 'POST') {
        const e = b, now = Date.now();
        if (e.v !== 1 || !uuid(e.id) || e.room !== room || e.sender !== s.device_id || !Number.isSafeInteger(e.created) || Math.abs(now - e.created) > 120000 || !Number.isSafeInteger(e.expires) || e.expires <= now || e.expires > e.created + 7 * 24 * HOUR) fail(400, 'Invalid message context or lifetime.');
        if (!b64(e.ciphertext, 2900000) || !b64(e.iv, 16) || e.iv.length !== 16 || !b64(e.signature, 88) || !Array.isArray(e.keys)) fail(400, 'Invalid encrypted envelope.');
        publicKey(e.ephemeral);
        const targets = devices(room);
        if (targets.length > 100 || e.keys.length !== targets.length || new Set(e.keys.map(k => k.device)).size !== targets.length) fail(409, 'Device list changed. Refresh the channel.');
        for (const k of e.keys) if (!targets.some(d => d.id === k.device && d.revision === k.revision) || !b64(k.iv, 16) || k.iv.length !== 16 || !b64(k.ciphertext, 64) || k.ciphertext.length !== 64) fail(409, 'Device key changed. Refresh and verify fingerprints.');
        const sender = targets.find(d => d.id === s.device_id);
        if (!sender || !verify('sha256', Buffer.from(unsignedEnvelope(e)), { key: createPublicKey({ key: sender.signing, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(e.signature, 'base64'))) { audit(s.user_id, 'message.integrity_failed', 'high'); fail(400, 'Message signature invalid.'); }
        if (one('SELECT 1 FROM replays WHERE id=?', e.id)) { audit(s.user_id, 'message.replay_blocked', 'warning'); fail(409, 'Replay rejected.'); }
        const clean = { ...JSON.parse(unsignedEnvelope(e)), signature: e.signature };
        db.exec('BEGIN');
        try { run('INSERT INTO replays VALUES(?,?)', e.id, now + 8 * 24 * HOUR); run('INSERT INTO messages VALUES(?,?,?,?,?,?)', e.id, room, e.sender, JSON.stringify(clean), e.created, e.expires); db.exec('COMMIT'); }
        catch (error) { db.exec('ROLLBACK'); throw error; }
        notify(room, { type: 'message', room, message: clean }); return { id: e.id };
      }
    }
    if (path === '/api/devices' && method === 'GET') return all(`SELECT d.id,d.label,d.revision,d.trusted,d.created,
      (SELECT MAX(seen) FROM sessions WHERE device_id=d.id) AS seen FROM devices d WHERE d.user_id=? ORDER BY d.created DESC`, s.user_id);
    if (path === '/api/devices/rotate' && method === 'POST') {
      fresh(s); const exchange = publicKey(b.exchange);
      const d = one('SELECT * FROM devices WHERE id=?', s.device_id);
      checkCertificate(d.id, d.revision + 1, exchange, JSON.parse(d.signing), b.certificate);
      run('UPDATE devices SET exchange=?,certificate=?,revision=revision+1 WHERE id=?', JSON.stringify(exchange), b.certificate, s.device_id);
      audit(s.user_id, 'device.key_rotated', 'warning', s.device_id); return { revision: one('SELECT revision FROM devices WHERE id=?', s.device_id).revision };
    }
    if (path === '/api/devices/revoke' && method === 'POST') {
      fresh(s); const d = one('SELECT * FROM devices WHERE id=? AND user_id=?', str(b.device), s.user_id);
      if (!d) fail(404, 'Device not found.');
      run('UPDATE devices SET trusted=0 WHERE id=?', d.id); run('UPDATE sessions SET revoked=1 WHERE device_id=?', d.id);
      audit(s.user_id, 'device.revoked', 'high', d.id); disconnectInvalid(); return { ok: true };
    }
    if (path === '/api/sessions/revoke' && method === 'POST') {
      fresh(s); const target = one('SELECT hash FROM sessions WHERE user_id=? AND substr(hash,1,16)=?', s.user_id, str(b.session, 16));
      if (!target) fail(404, 'Session not found.');
      run('UPDATE sessions SET revoked=1 WHERE hash=?', target.hash); audit(s.user_id, 'session.revoked', 'warning'); disconnectInvalid(); return { ok: true };
    }
    if (path === '/api/security' && method === 'GET') {
      const events = s.role === 'admin' ? all('SELECT * FROM audit ORDER BY id DESC LIMIT 100') : all('SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 100', s.user_id);
      return { events, sessions: all('SELECT substr(hash,1,16) AS id,device_id,created,expires,seen,revoked FROM sessions WHERE user_id=? ORDER BY created DESC LIMIT 50', s.user_id).map(v => ({ ...v, current: v.id === s.hash.slice(0,16) })),
        stats: { activeSessions: one('SELECT COUNT(*) AS n FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.user_id=? AND s.revoked=0 AND d.trusted=1 AND s.expires>? AND s.seen>?', s.user_id, Date.now(), Date.now() - 30 * 60000).n,
          trustedDevices: one('SELECT COUNT(*) AS n FROM devices WHERE user_id=? AND trusted=1', s.user_id).n,
          alerts: events.filter(e => ['warning', 'high'].includes(e.severity)).length } };
    }
    if (path === '/api/admin/revoke' && method === 'POST') {
      if (s.role !== 'admin') fail(403, 'Administrator role required.'); fresh(s);
      const target = str(b.user); if (target === s.user_id) fail(400, 'Cannot revoke your own administrator account.');
      if (!one('SELECT 1 FROM users WHERE id=?', target)) fail(404, 'Account not found.');
      run('UPDATE users SET revoked=1 WHERE id=?', target); run('UPDATE sessions SET revoked=1 WHERE user_id=?', target);
      audit(s.user_id, 'account.revoked', 'high', target); disconnectInvalid(); return { ok: true };
    }
    fail(404, 'Not found.');
  }
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      const path = new URL(req.url, origin).pathname;
      if (path.startsWith('/api/')) {
        const result = await api(req, res, path); res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(result));
      } else {
        if (!['GET', 'HEAD'].includes(req.method)) fail(405, 'Method not allowed.');
        const routes = { '/': 'public/index.html', '/app.js': 'public/app.js', '/styles.css': 'public/styles.css', '/crypto.js': 'public/crypto.js', '/shared/protocol.js': 'shared/protocol.js' };
        const file = routes[path]; if (!file) fail(404, 'Not found.');
        const bytes = await readFile(resolve(ROOT, file));
        res.setHeader('Content-Type', ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' })[extname(file)]);
        res.end(req.method === 'HEAD' ? undefined : bytes);
      }
    } catch (error) {
      // Never log request bodies, headers, cookies, credentials or cryptographic material.
      res.statusCode = error.status || 500; res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: error.status ? error.message : 'Request could not be completed.' }));
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    try {
      if (req.headers.origin !== origin || req.url !== '/ws') fail(403, 'Origin denied');
      const s = session(req); rate(`ws:${s.hash}`, 10);
      if ([...clients].filter(c => c.hash === s.hash).length >= 3) fail(429, 'Connection limit');
      wss.handleUpgrade(req, socket, head, ws => {
        const c = { ws, req, hash: s.hash }; clients.add(c);
        ws.on('error', () => {}); ws.on('close', () => clients.delete(c));
        ws.on('message', () => { try { session(req); } catch { ws.close(4001, 'Session revoked'); } });
        ws.send(JSON.stringify({ type: 'connected' }));
      });
    } catch { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); socket.destroy(); }
  });
  const timer = setInterval(() => {
    const now = Date.now(); disconnectInvalid();
    run('DELETE FROM messages WHERE expires<?', now); run('DELETE FROM replays WHERE expires<?', now);
    run('DELETE FROM audit WHERE created<?', now - 30 * 24 * HOUR);
    run('DELETE FROM sessions WHERE expires<?', now - 24 * HOUR);
    run('DELETE FROM users WHERE active=0 AND created<?', now - HOUR);
    for (const [key, val] of limits) if (val.until < now) limits.delete(key);
    for (const [key, val] of challenges) if (val.until < now) challenges.delete(key);
    for (const c of clients) if (c.ws.readyState === WebSocket.OPEN) c.ws.ping();
  }, 5000); timer.unref();
  return { server, db, close: async () => { clearInterval(timer); for (const c of clients) c.ws.terminate(); wss.close(); await new Promise(r => server.close(r)); db.close(); } };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const app = createApp(), host = process.env.HOST || '127.0.0.1', port = Number(process.env.PORT || 3000);
  app.server.listen(port, host, () => console.log(`Cipherroom listening at ${process.env.APP_ORIGIN || `http://${host}:${port}`}`));
}
