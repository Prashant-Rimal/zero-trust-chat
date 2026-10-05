import { createVault, unlockVault, saveVault, publicIdentity, fingerprint, encryptMessage, decryptMessage, rotateExchange, verifyDevice, base64, unbase64 } from './crypto.js';

const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
let authMode = 'login', challenge, vault, username, me, rooms = [], currentRoom, currentDevices = [], users = [], socket, attachment;
let seen = new Set(), processing = Promise.resolve(), currentView = 'chat', generation = 0;
const nodes = new Map();
const vaultName = name => `cipherroom.v1.${name}`;
function el(tag, className, text) { const n = document.createElement(tag); if (className) n.className = className; if (text !== undefined) n.textContent = text; return n; }
function button(text, action, className = 'secondary') { const b = el('button', className, text); b.type = 'button'; b.addEventListener('click', () => guard(action)); return b; }
function toast(message, error = false) { $('#toast').textContent = message; $('#toast').classList.toggle('error', error); $('#toast').hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => $('#toast').hidden = true, 6500); }
async function guard(fn) { try { await fn(); } catch (e) { toast(e.message || 'Something went wrong.', true); } }
function copyFingerprintButton(value) {
  return button('Copy fingerprint', async () => {
    try { await navigator.clipboard.writeText(value); }
    catch { throw new Error('Could not copy fingerprint. Select and copy the displayed fingerprint manually.'); }
    toast('Fingerprint copied. Compare it over a trusted, separate channel.');
  });
}
async function api(path, method = 'GET', data) {
  const response = await fetch(`/api${path}`, { method, headers: { 'Content-Type': 'application/json', ...(me ? { 'X-CSRF-Token': me.csrf } : {}) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  const result = await response.json();
  if (!response.ok) { if (response.status === 401 && me && !path.includes('stepup')) lock(); throw new Error(result.error); }
  return result;
}
async function persist() { localStorage.setItem(vaultName(username), JSON.stringify(await saveVault(vault.identity, vault.key, vault.salt))); }
function resetAuth() { challenge = null; $('#auth-form').hidden = false; $('#auth-tabs').hidden = false; $('#mfa-form').hidden = true; $('#auth-title').textContent = authMode === 'login' ? 'Welcome back.' : 'Make room for privacy.'; $('#auth-subtitle').textContent = authMode === 'login' ? 'Unlock your private workspace.' : 'Your keys. Your people. Your conversation.'; }
$$('[data-auth]').forEach(b => b.addEventListener('click', () => { authMode = b.dataset.auth; $$('[data-auth]').forEach(t => t.classList.toggle('active', t === b)); $('#auth-submit').textContent = authMode === 'login' ? 'Unlock workspace ↗' : 'Create secure account ↗'; $('#auth-form [name=password]').autocomplete = authMode === 'login' ? 'current-password' : 'new-password'; resetAuth(); }));
$('#auth-back').addEventListener('click', resetAuth);
$('#auth-form').addEventListener('submit', e => { e.preventDefault(); guard(async () => {
  const submit = $('#auth-submit'); submit.disabled = true;
  try {
    const data = new FormData(e.target); username = data.get('username').trim().toLowerCase(); const password = data.get('password');
    const stored = localStorage.getItem(vaultName(username));
    if (stored) { try { vault = await unlockVault(JSON.parse(stored), password); } catch { throw new Error('Could not unlock this browser’s key vault. Check your password.'); } }
    else vault = await createVault(password);
    const result = await api(authMode === 'login' ? '/login' : '/register', 'POST', { username, password });
    await persist(); challenge = result.challenge;
    $('#auth-form').hidden = true; $('#auth-tabs').hidden = true; $('#mfa-form').hidden = false;
    $('#auth-title').textContent = result.secret ? 'One more layer.' : 'Verify it’s you.';
    $('#auth-subtitle').textContent = result.secret ? 'Set up two-factor authentication to continue.' : 'Enter a fresh code from your authenticator app.';
    $('#enrollment').hidden = !result.secret; $('#totp-secret').textContent = result.secret || '';
    $('#mfa-form [name=code]').value = ''; $('#mfa-form [name=code]').focus(); $('#auth-form [name=password]').value = '';
  } finally { submit.disabled = false; }
}); });
$('#copy-secret').addEventListener('click', () => guard(async () => { await navigator.clipboard.writeText($('#totp-secret').textContent); toast('Setup key copied. Keep it private.'); }));
$('#mfa-form').addEventListener('submit', e => { e.preventDefault(); guard(async () => {
  const submit = e.target.querySelector('[type=submit]'); submit.disabled = true;
  try {
    const data = new FormData(e.target), request = identity => api('/auth/verify', 'POST', { challenge, code: data.get('code'), label: data.get('label'), ...publicIdentity(identity) });
    // A staged rotation survives interruption between the server update and local commit.
    if (vault.identity.pendingRotation) {
      const next = { ...vault.identity, ...vault.identity.pendingRotation }; delete next.pendingRotation;
      try { me = await request(next); vault.identity = next; }
      catch (error) { if (!error.message.includes('Device is revoked or its identity changed')) throw error; me = await request(vault.identity); delete vault.identity.pendingRotation; }
      await persist();
    } else me = await request(vault.identity);
    $('#totp-secret').textContent = ''; $('#mfa-form [name=code]').value = ''; await enter();
  }
  finally { submit.disabled = false; }
}); });
async function enter() {
  $('#auth-screen').hidden = true; $('#workspace').hidden = false;
  $('#current-user').textContent = `@${me.user.username}`; $('#avatar').textContent = me.user.username.slice(0, 2).toUpperCase();
  $('#workspace-role').textContent = `${me.user.role.toUpperCase()} ACCESS`;
  users = await api('/users'); await refreshRooms(); connect();
  if (rooms.length) await openRoom(rooms[0].id); await showView('chat');
}
function lock() {
  me = null; vault = null; attachment = null; currentRoom = null; generation++; seen.clear(); nodes.clear(); rooms = []; currentDevices = [];
  if (socket) { socket.onclose = null; socket.close(); socket = null; }
  $('#workspace').hidden = true; $('#auth-screen').hidden = false; $('#message-list').replaceChildren(); $('#message-input').value = ''; $('#message-input').disabled = true; $('#send-button').disabled = true; $('#attach-button').disabled = true;
  $('#modal').close(); $('#modal-body').replaceChildren(); $('#security-view').replaceChildren(); $('#devices-view').replaceChildren(); $('#room-list').replaceChildren(); $('#attachment-preview').hidden = true; resetAuth();
}
$('#logout').addEventListener('click', () => guard(async () => { await api('/logout', 'POST', {}); lock(); toast('Workspace locked. Private keys cleared from app state.'); }));
function connect() {
  if (!me) return; if (socket) { socket.onclose = null; socket.close(); }
  socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  socket.onopen = () => { $('#connection').lastChild.textContent = ' Live connection'; };
  socket.onmessage = event => guard(async () => {
    const data = JSON.parse(event.data);
    if (data.type === 'rooms') await refreshRooms();
    if (data.type === 'members' && currentRoom?.id === data.room) await openRoom(data.room);
    if (data.type === 'message' && currentRoom?.id === data.room) { const token = generation; processing = processing.then(() => displayMessage(data.message, token)).catch(e => toast(e.message, true)); }
  });
  socket.onclose = event => {
    $('#connection').lastChild.textContent = ' Reconnecting';
    if (event.code === 4001) { lock(); toast('Session revoked or expired. Sign in again.', true); }
    else if (me) setTimeout(() => guard(async () => { if (!me) return; await api('/me'); connect(); if (currentRoom) await openRoom(currentRoom.id); }), 2500);
  };
}
async function refreshRooms() {
  rooms = await api('/rooms'); $('#room-count').textContent = rooms.length; $('#room-list').replaceChildren();
  for (const r of rooms) {
    const b = button('', () => openRoom(r.id), `room-button${r.id === currentRoom?.id ? ' active' : ''}`);
    b.append(el('span', '', r.kind === 'group' ? '#' : '◎'), el('span', 'room-title', r.name), el('small', '', r.member_count)); $('#room-list').append(b);
  }
  if (!rooms.length) $('#room-list').append(el('p', 'empty-channels', 'No channels yet. Make your first connection.'));
}
async function checkPins(devices) {
  let changed = false;
  for (const d of devices) {
    await verifyDevice(d);
    const fp = await fingerprint(d.signing), pin = vault.identity.pins[d.id];
    if (pin && pin.fingerprint !== fp) throw new Error(`Identity key changed for ${d.username}. Messaging blocked. Verify out of band before using a new channel or device.`);
    if (pin && (d.revision < pin.revision || (d.revision === pin.revision && pin.certificate !== d.certificate))) throw new Error('Device key rollback or substitution blocked.');
    if (!pin) { vault.identity.pins[d.id] = { fingerprint: fp, verified: d.id === me.device, revision: d.revision, certificate: d.certificate }; changed = true; }
    else if (d.revision > pin.revision) { pin.revision = d.revision; pin.certificate = d.certificate; changed = true; toast(`Encryption key rotated for ${d.username}. Signed identity verified.`); }
  }
  if (changed) { await persist(); if (devices.some(d => d.id !== me.device && !vault.identity.pins[d.id].verified)) toast('New device keys pinned. Compare fingerprints with your participants.'); }
}
async function openRoom(id) {
  const r = rooms.find(r => r.id === id); if (!r) return;
  const token = ++generation; currentRoom = r; seen = new Set(); nodes.clear(); $('#message-list').replaceChildren();
  $('#message-input').disabled = true; $('#send-button').disabled = true; $('#attach-button').disabled = true;
  $('#channel-name').textContent = r.name; $('#channel-avatar').textContent = r.kind === 'group' ? '#' : '◎';
  $('#channel-meta').textContent = `${r.member_count} participants · Encrypted channel`;
  await showView('chat'); await refreshRooms();
  const devices = await api(`/rooms/${id}/devices`); await checkPins(devices);
  if (token !== generation) return; currentDevices = devices;
  const messages = await api(`/rooms/${id}/messages`); if (token !== generation) return;
  $('#message-list').append(el('div', 'date-divider', 'YOUR ENCRYPTED CONVERSATION'));
  if (!messages.length) $('#message-list').append(el('p', 'empty-panel room-empty', 'The start of something private. Say hello.'));
  for (const message of messages) await displayMessage(message, token);
  if (token !== generation) return;
  $('#message-input').disabled = false; $('#send-button').disabled = false; $('#attach-button').disabled = false; $('#message-input').focus();
}
async function displayMessage(e, token = generation) {
  if (!me || token !== generation || e.room !== currentRoom?.id || e.expires <= Date.now() || seen.has(e.id)) return;
  seen.add(e.id);
  try {
    let sender = currentDevices.find(d => d.id === e.sender);
    if (!sender) { const updated = await api(`/rooms/${e.room}/devices`); await checkPins(updated); if (token !== generation) return; currentDevices = updated; sender = updated.find(d => d.id === e.sender); }
    if (!sender) throw new Error('Sender device is no longer trusted.');
    const clear = await decryptMessage(vault.identity, e, sender);
    if (token !== generation || e.expires <= Date.now()) return;
    $('.room-empty')?.remove(); const mine = e.sender === me.device;
    const row = el('article', `message${mine ? ' mine' : ''}`); row.dataset.messageId = e.id;
    row.append(el('div', 'avatar', sender.username.slice(0, 2).toUpperCase()));
    const content = el('div', 'message-content'), meta = el('div', 'message-meta');
    meta.append(el('span', '', mine ? 'You' : sender.username), el('time', '', new Date(e.created).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })));
    const bubble = el('div', 'bubble', typeof clear.text === 'string' ? clear.text : '');
    if (clear.file && typeof clear.file.data === 'string') bubble.append(button(`↓  ${String(clear.file.name).slice(0, 200)} · encrypted attachment`, () => {
      const blob = new Blob([unbase64(clear.file.data)], { type: 'application/octet-stream' }), url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = String(clear.file.name).replace(/[\\/]/g, '_'); a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }, 'attachment-download'));
    const status = el('div', 'message-status', `✓ Integrity verified · expires ${new Date(e.expires).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}`);
    content.append(meta, bubble, status); row.append(content); $('#message-list').append(row); nodes.set(e.id, { node: row, expires: e.expires });
    $('#message-list').scrollTop = $('#message-list').scrollHeight;
  } catch (error) {
    if (token !== generation) return; const n = el('div', 'message-error', `◇ Protected message unavailable: ${error.message}`); $('#message-list').append(n); nodes.set(e.id, { node: n, expires: e.expires });
  }
}
setInterval(() => { for (const [id, m] of nodes) if (m.expires <= Date.now()) { m.node.remove(); nodes.delete(id); } }, 1000);
$('#message-form').addEventListener('submit', e => { e.preventDefault(); guard(async () => {
  if (!currentRoom || (!$('#message-input').value.trim() && !attachment)) return;
  const room = currentRoom, text = $('#message-input').value, file = attachment; $('#send-button').disabled = true;
  try {
    const devices = await api(`/rooms/${room.id}/devices`); await checkPins(devices); currentDevices = devices;
    const start = performance.now(); const encrypted = await encryptMessage(vault.identity, room.id, devices, { text, ...(file ? { file } : {}) }, Number($('#expiry').value));
    const encryptMs = performance.now() - start; await api(`/rooms/${room.id}/messages`, 'POST', encrypted);
    if (room.id === currentRoom?.id) { $('#message-input').value = ''; attachment = null; $('#attachment-preview').hidden = true; await displayMessage(encrypted); }
    $('#encryption-timing').textContent = `Encrypted in ${encryptMs.toFixed(1)} ms · delivered in ${(performance.now() - start).toFixed(0)} ms`;
  } finally { $('#send-button').disabled = !currentRoom; }
}); });
$('#message-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); if (!$('#send-button').disabled) $('#message-form').requestSubmit(); } });
$('#attach-button').addEventListener('click', () => $('#file-input').click());
$('#file-input').addEventListener('change', () => guard(async () => {
  const file = $('#file-input').files[0]; if (!file) return; if (file.size > 1500000) { $('#file-input').value = ''; throw new Error('Choose a file smaller than 1.5 MB for this prototype.'); }
  attachment = { name: file.name, data: base64(await file.arrayBuffer()) }; $('#attachment-preview').replaceChildren(el('span', '', `◇ ${file.name} · ${(file.size / 1024).toFixed(0)} KB · will be encrypted`), button('×', () => { attachment = null; $('#attachment-preview').hidden = true; }, ''));
  $('#attachment-preview').hidden = false; $('#file-input').value = '';
}));
function modal(title) { $('#modal-title').textContent = title; $('#modal-body').replaceChildren(); if (!$('#modal').open) $('#modal').showModal(); return $('#modal-body'); }
$('#close-modal').addEventListener('click', () => $('#modal').close());
$('#modal').addEventListener('click', e => { if (e.target === $('#modal') && (e.offsetX < 0 || e.offsetX > $('#modal').offsetWidth || e.offsetY < 0 || e.offsetY > $('#modal').offsetHeight)) $('#modal').close(); });
async function newRoom() {
  users = await api('/users'); const body = modal('Start a conversation'); body.append(el('p', '', 'Invite people into a space only your devices can read.'));
  const form = el('form'); form.innerHTML = '<label>Channel name<input name="name" placeholder="e.g. Design team" maxlength="60" required></label><label>Conversation type<select name="kind"><option value="group">Group channel</option><option value="direct">Direct message</option></select></label><p class="muted">Choose participants</p><div class="member-options"></div><button type="submit" class="primary full">Create encrypted channel ↗</button>';
  for (const u of users.filter(u => u.id !== me.user.id)) { const label = el('label', 'member-option'), input = el('input'); input.type = 'checkbox'; input.name = 'members'; input.value = u.id; label.append(input, el('span', '', `@${u.username}`)); form.querySelector('.member-options').append(label); }
  if (users.length < 2) form.querySelector('.member-options').append(el('p', 'notice', 'Invite a teammate to create an account using another browser or private window on this computer. Then reopen this dialog.'));
  form.addEventListener('submit', e => { e.preventDefault(); guard(async () => { const data = new FormData(form); const result = await api('/rooms', 'POST', { name: data.get('name'), kind: data.get('kind'), members: data.getAll('members') }); $('#modal').close(); await refreshRooms(); await openRoom(result.id); toast('Your encrypted channel is ready.'); }); }); body.append(form);
}
$('#new-room').addEventListener('click', () => guard(newRoom)); $('#welcome-create').addEventListener('click', () => guard(newRoom));
$('#channel-info').addEventListener('click', () => guard(async () => {
  if (!currentRoom) return; const devices = await api(`/rooms/${currentRoom.id}/devices`); await checkPins(devices); const body = modal('People & identity keys');
  body.append(el('p', '', 'Compare these fingerprints with each person over a trusted, separate channel before marking them verified. First-use pinning alone cannot detect a malicious server at first contact.'));
  for (const d of devices) { const card = el('div', 'fingerprint-card'), pin = vault.identity.pins[d.id]; card.append(el('strong', '', `${d.username} · ${d.label}`), el('p', '', `${pin.verified ? '✓ Verified identity' : '○ Pinned, not yet verified'} · key epoch ${d.revision}`), el('code', 'fingerprint', pin.fingerprint));
    card.append(copyFingerprintButton(pin.fingerprint));
    if (!pin.verified) card.append(button('I compared this fingerprint', async () => { pin.verified = true; await persist(); toast('Identity fingerprint marked verified.'); $('#modal').close(); })); body.append(card); }
  if (currentRoom.owner === me.user.id) { const members = await api(`/rooms/${currentRoom.id}/members`); for (const u of members.filter(u => u.id !== me.user.id)) body.append(button(`Remove @${u.username} from channel`, async () => { await api(`/rooms/${currentRoom.id}/members`, 'DELETE', { user: u.id }); $('#modal').close(); await refreshRooms(); await openRoom(currentRoom.id); toast('Member removed. Future messages exclude their devices.'); }, 'text-button full')); }
}));
$$('[data-view]').forEach(b => b.addEventListener('click', () => guard(() => showView(b.dataset.view))));
async function showView(view) {
  currentView = view; $$('.view').forEach(n => n.hidden = n.id !== `${view}-view`); $$('[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $('#page-breadcrumb').textContent = ({ chat: 'MESSAGES', security: 'SECURITY CENTER', devices: 'MY DEVICES', privacy: 'PRIVACY MODEL' })[view];
  if (view === 'security') await renderSecurity(); if (view === 'devices') await renderDevices(); if (view === 'privacy') renderPrivacy();
}
function pageHeading(target, eyebrow, title, description) {
  target.replaceChildren(); const row = el('div', 'page-title-row'), copy = el('div'); copy.append(el('span', 'eyebrow', eyebrow), el('h1', '', title), el('p', '', description)); row.append(copy); target.append(row); return row;
}
function stepup() {
  const body = modal('Verify your identity'); body.append(el('p', '', 'Sensitive actions require a second factor verified within the last five minutes. Use a fresh, unused authenticator code.'));
  const form = el('form'); form.innerHTML = '<label>Authenticator code<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="000000"></label><button class="primary full">Verify identity ↗</button>';
  form.addEventListener('submit', e => { e.preventDefault(); guard(async () => { await api('/stepup', 'POST', { code: new FormData(form).get('code') }); $('#modal').close(); toast('Identity verified for five minutes. Retry your sensitive action.'); }); }); body.append(form);
}
const eventNames = { 'session.started': 'Secure session started', 'device.enrolled': 'New device enrolled', 'session.stepup': 'Identity re-verified', 'login.failed': 'Unsuccessful sign-in detected', 'mfa.failed': 'Second-factor challenge rejected', 'device.revoked': 'Device access revoked', 'device.key_rotated': 'Encryption key rotated', 'account.revoked': 'Account access revoked', 'message.replay_blocked': 'Replayed message blocked', 'message.integrity_failed': 'Message integrity check failed', 'channel.created': 'Encrypted channel created', 'channel.member_removed': 'Channel membership revoked' };
async function renderSecurity() {
  const data = await api('/security'), target = $('#security-view'); const heading = pageHeading(target, 'VISIBILITY WITHOUT SURVEILLANCE', 'Security center', 'A clear view of your workspace’s security. No message content, ever.');
  heading.append(button('◇ Verify identity', stepup)); const grid = el('div', 'stat-grid');
  for (const [label, value, hint] of [['Active sessions', data.stats.activeSessions, 'Continuously verified'], ['Trusted devices', data.stats.trustedDevices, 'MFA-enrolled endpoints'], ['Security signals', data.stats.alerts, 'Warnings in recent events']]) { const card = el('div', 'stat-card'); card.append(el('span', '', label), el('strong', '', value), el('small', '', hint)); grid.append(card); } target.append(grid);
  const panel = el('section', 'panel'); panel.append(el('h3', '', 'Activity & security signals'), el('p', '', `${me.user.role === 'admin' ? 'Workspace-wide administrative visibility' : 'Your account activity'} · latest 100 events · 30-day retention`));
  for (const event of data.events) { const row = el('div', 'event-row'), detail = el('div'); detail.append(el('strong', '', eventNames[event.kind] || event.kind), el('small', '', event.severity === 'info' ? 'Verified system event' : 'Review device and session activity')); row.append(el('span', `event-icon ${event.severity}`, event.severity === 'info' ? '◇' : '!'), detail, el('time', '', new Date(event.created).toLocaleString())); panel.append(row); } target.append(panel);
  if (me.user.role === 'admin') { const admin = el('section', 'panel'); admin.append(el('h3', '', 'Account containment'), el('p', '', 'Revoke a compromised account and disconnect all its sessions. This prototype has no self-service restoration.'));
    const list = el('div'); list.id = 'admin-users'; for (const u of (await api('/users')).filter(u => u.id !== me.user.id)) { const entry = el('div', 'admin-user', `@${u.username}`); entry.append(button('Revoke access', () => confirmAction('Revoke account access?', `This immediately blocks @${u.username} and all of their devices.`, async () => { await api('/admin/revoke', 'POST', { user: u.id }); await renderSecurity(); }), '')); list.append(entry); } admin.append(list); target.append(admin); }
}
function confirmAction(title, message, action) { const body = modal(title); body.append(el('p', 'notice danger-notice', message)); const actions = el('div', 'modal-actions'); actions.append(button('Cancel', () => $('#modal').close()), button('Confirm', async () => { await action(); $('#modal').close(); }, 'primary')); body.append(actions); }
async function renderDevices() {
  const data = await api('/devices'), target = $('#devices-view'); const heading = pageHeading(target, 'TRUST IS CONTINUOUS', 'Your devices. Your control.', 'Every device has its own identity and encryption keys. Revoke access at any time.'); heading.append(button('◇ Verify identity', stepup));
  target.append(el('p', 'notice', 'Zero Trust in practice: account status, device trust, membership and session lifetime are rechecked on each request. Revocation disconnects active sessions.'));
  for (const d of data) { const card = el('div', 'device-card'), detail = el('div', 'device-detail'), title = el('h3', '', d.label); if (d.id === me.device) title.append(el('span', 'badge', 'THIS DEVICE')); detail.append(title, el('p', '', `${d.trusted ? '● Trusted' : '○ Revoked'} · epoch ${d.revision} · last active ${d.seen ? new Date(d.seen).toLocaleString() : 'never'}`)); const actions = el('div', 'device-actions');
    if (d.id === me.device) actions.append(button('Rotate key', () => confirmAction('Rotate your encryption key?', 'This discards the current private exchange key. Older messages will become unreadable on this device. It limits retrospective decryption after rotation, but is not a full Double Ratchet.', async () => {
      const next = await rotateExchange(vault.identity);
      vault.identity.pendingRotation = { exchange: next.exchange, revision: next.revision, certificate: next.certificate }; await persist();
      try {
        await api('/devices/rotate', 'POST', { exchange: publicIdentity(next).exchange, certificate: next.certificate }); vault.identity = next; delete vault.identity.pendingRotation; await persist();
      } catch (error) { lock(); throw new Error(`Rotation interrupted. Sign in again to reconcile the saved keys. ${error.message}`); }
      nodes.clear(); seen.clear(); $('#message-list').replaceChildren(); await renderDevices(); toast('Key rotated. Prior message keys discarded from the active vault.');
    })));
    if (d.trusted) actions.append(button('Revoke', () => confirmAction('Revoke this device?', 'Active sessions will be disconnected and future encrypted messages will exclude this device. A revoked device identity cannot sign in again.', async () => { await api('/devices/revoke', 'POST', { device: d.id }); if (d.id === me.device) lock(); else await renderDevices(); }), 'secondary danger'));
    card.append(el('span', 'device-symbol', '▣'), detail, actions); target.append(card);
  }
  const fp = await fingerprint(vault.identity.signing);
  const panel = el('section', 'panel'); panel.append(el('h3', '', 'Your identity fingerprint'), el('p', '', 'Share this over a trusted channel to verify this device. This is public key information, not a secret.'), el('code', 'fingerprint', fp), copyFingerprintButton(fp)); target.append(panel);
  const sessions = (await api('/security')).sessions, sessionPanel = el('section', 'panel'); sessionPanel.append(el('h3', '', 'Session activity'), el('p', '', 'Sessions expire after 8 hours, or 30 minutes without API activity. End an individual session without revoking its device.'));
  for (const s of sessions) {
    const row = el('div', 'event-row'), detail = el('div'), active = !s.revoked && s.expires > Date.now() && s.seen > Date.now() - 1800000;
    detail.append(el('strong', '', `${s.current ? 'This session' : 'Browser session'} · ${active ? 'Active' : 'Ended'}`), el('small', '', `Last active ${new Date(s.seen).toLocaleString()}`)); row.append(el('span', 'event-icon', '◷'), detail);
    if (active) row.append(button('End session', () => confirmAction('End this session?', 'This signs out the selected session. The device remains trusted for future sign-ins.', async () => { await api('/sessions/revoke', 'POST', { session: s.id }); if (s.current) lock(); else await renderDevices(); }), 'text-button')); sessionPanel.append(row);
  } target.append(sessionPanel);
}
function renderPrivacy() {
  const target = $('#privacy-view'); pageHeading(target, 'NOTHING TO HIDE. LESS TO EXPOSE.', 'Privacy, made visible.', 'Understand exactly where your trust goes — and where it doesn’t.');
  const flow = el('div', 'flow'); flow.innerHTML = '<div>▣ Your device<small>Encrypts locally</small></div><span>→</span><div>◇ Relay server<small>Stores ciphertext</small></div><span>→</span><div>▣ Their device<small>Decrypts locally</small></div>'; target.append(flow);
  const grid = el('div', 'privacy-grid');
  const sections = [
    ['What stays private', ['Message text and attachment bytes are encrypted with a fresh AES-256-GCM key for each message.', 'Attachment filenames are encrypted inside the payload.', 'Private identity and exchange keys stay in your browser’s password-encrypted vault.', 'Message content never enters application server logs.']],
    ['What the server can see', ['Usernames, public device keys, roles, channel names and membership.', 'Sender and recipient device IDs, ciphertext sizes, send times and expiration times.', 'Your connection IP exists at the network layer; this app does not retain it in audit records.', 'Security event types and timestamps are retained for 30 days.']],
    ['Trust, checked continuously', ['Password + authenticator code are required for every sign-in.', 'Device trust and session validity are checked on API calls and WebSocket delivery.', 'Administrative and device changes require recent second-factor verification.', 'Revocation cuts off future access; it cannot retract content already read or copied.']],
    ['Understand the limits', ['This is an educational prototype, not an audited Signal implementation.', 'Fingerprints are pinned on first use. Compare them out of band to resist initial key substitution.', 'Key rotation deletes the active previous exchange key; it does not implement per-message forward secrecy or post-compromise recovery.', 'A malicious server serving altered JavaScript or a compromised endpoint can defeat browser encryption. Expiration is not guaranteed secure erasure from backups or recipient devices.']]
  ];
  for (const [title, lines] of sections) { const panel = el('section', 'panel'), list = el('ul'); panel.append(el('h3', '', title)); for (const line of lines) list.append(el('li', '', line)); panel.append(list); grid.append(panel); } target.append(grid);
}
// No plaintext persistence, service worker, external analytics or remote font requests.
document.addEventListener('visibilitychange', () => { if (!document.hidden && me) guard(async () => { await api('/me'); if (currentView === 'chat' && currentRoom) await openRoom(currentRoom.id); }); });
