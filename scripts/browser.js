import { chromium } from '@playwright/test';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { createApp } from '../server/index.js';
import { totp } from '../server/security.js';

const directory = mkdtempSync(join(tmpdir(), 'cipherroom-browser-')), origin = 'http://127.0.0.1:3199';
const app = createApp({ directory, origin }); app.server.listen(3199, '127.0.0.1'); await once(app.server, 'listening');
const browser = await chromium.launch({ headless: true, ...(process.platform === 'win32' ? { channel: 'chrome' } : {}) });
const checks = [], errors = [];
mkdirSync('evidence/screenshots', { recursive: true });
const a = await browser.newContext({ viewport: { width: 1440, height: 1000 } }), b = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const alice = await a.newPage(), bob = await b.newPage();
for (const page of [alice, bob]) page.on('pageerror', e => errors.push(e.message));
async function register(page, username, label) {
  await page.goto(origin); await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await page.locator('#auth-form [name=username]').fill(username); await page.locator('#auth-form [name=password]').fill('Browser-lab-password-123!');
  await page.locator('#auth-submit').click(); await page.locator('#totp-secret').waitFor({ state: 'visible' });
  const secret = await page.locator('#totp-secret').textContent();
  await page.locator('#mfa-form [name=code]').fill(totp(secret)); await page.locator('#mfa-form [name=label]').fill(label);
  await page.getByRole('button', { name: 'Verify & enter' }).click(); await page.locator('#workspace').waitFor({ state: 'visible' });
  return secret;
}
try {
  await alice.goto(origin); await alice.screenshot({ path: 'evidence/screenshots/sign-in.png', fullPage: true });
  await register(alice, 'alex.morgan', 'Alex · Chrome'); await register(bob, 'jamie.chen', 'Jamie · Chrome'); checks.push('Two independent browser contexts complete mandatory MFA enrollment');
  await alice.locator('#new-room').click(); await alice.locator('#modal [name=name]').fill('Design studio'); await alice.getByText('@jamie.chen', { exact: true }).click(); await alice.getByRole('button', { name: 'Create encrypted channel' }).click();
  await alice.locator('#message-input').waitFor({ state: 'visible' });
  await bob.locator('.room-button').filter({ hasText: 'Design studio' }).click();
  await alice.locator('#message-input').fill('Hey Jamie — this is our private space for the new project. ✨'); await alice.locator('#send-button').click();
  await bob.getByText('Hey Jamie — this is our private space for the new project. ✨', { exact: true }).waitFor(); checks.push('Group message delivered over WebSocket and decrypted in the recipient browser');
  await bob.locator('#message-input').fill('Love it. I’ve got the first concepts ready to share.'); await bob.locator('#send-button').click(); await alice.getByText('Love it. I’ve got the first concepts ready to share.', { exact: true }).waitFor();
  await alice.locator('#message-input').fill('Perfect. Only our devices hold the keys — let’s keep the ideas here.'); await alice.locator('#send-button').click(); await bob.getByText('Perfect. Only our devices hold the keys — let’s keep the ideas here.', { exact: true }).waitFor();
  await bob.locator('#file-input').setInputFiles({ name: 'project-notes.txt', mimeType: 'text/plain', buffer: Buffer.from('Encrypted attachment test: private project notes.') }); await bob.locator('#message-input').fill('The notes are attached. Even the filename is encrypted in transit.'); await bob.locator('#send-button').click();
  await alice.getByRole('button', { name: /project-notes.txt/ }).waitFor();
  const downloaded = alice.waitForEvent('download'); await alice.getByRole('button', { name: /project-notes.txt/ }).click(); const download = await downloaded; assert.equal(download.suggestedFilename(), 'project-notes.txt'); checks.push('Encrypted file upload, delivery and local download');
  await alice.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
      writeText: async value => { if (window.rejectClipboard) throw new Error('Clipboard denied'); window.copiedFingerprint = value; }
    } });
  });
  await alice.locator('#channel-info').click();
  const cards = alice.locator('.fingerprint-card');
  for (const card of await cards.all()) {
    const status = await card.locator('p').textContent();
    await card.getByRole('button', { name: 'Copy fingerprint', exact: true }).click();
    await alice.getByText('Fingerprint copied. Compare it over a trusted, separate channel.', { exact: true }).waitFor();
    assert.equal(await alice.evaluate(() => window.copiedFingerprint), await card.locator('code').textContent());
    assert.equal(await card.locator('p').textContent(), status);
  }
  await alice.evaluate(() => { window.rejectClipboard = true; });
  await cards.first().getByRole('button', { name: 'Copy fingerprint', exact: true }).click();
  await alice.locator('#toast.error').getByText('Could not copy fingerprint. Select and copy the displayed fingerprint manually.', { exact: true }).waitFor();
  assert.equal(await alice.getByRole('button', { name: 'I compared this fingerprint' }).count(), 1);
  await alice.evaluate(() => { window.rejectClipboard = false; });
  checks.push('Copy full participant fingerprints without verifying identities; clipboard failure offers manual copying');
  await alice.getByRole('button', { name: 'I compared this fingerprint' }).click(); checks.push('Identity fingerprint verification');
  await alice.locator('#toast').waitFor({ state: 'hidden' }); await alice.screenshot({ path: 'evidence/screenshots/chat-desktop.png', fullPage: true });
  await alice.locator('.nav-item[data-view=security]').click(); await alice.getByRole('heading', { name: 'Security center' }).waitFor(); await alice.screenshot({ path: 'evidence/screenshots/security-desktop.png', fullPage: true }); checks.push('Live security dashboard and administrator controls');
  await alice.locator('.nav-item[data-view=devices]').click(); await alice.getByRole('heading', { name: 'Your devices. Your control.' }).waitFor(); await alice.screenshot({ path: 'evidence/screenshots/devices-desktop.png', fullPage: true });
  await alice.getByRole('button', { name: 'Copy fingerprint', exact: true }).click();
  await alice.getByText('Fingerprint copied. Compare it over a trusted, separate channel.', { exact: true }).waitFor();
  assert.equal(await alice.evaluate(() => window.copiedFingerprint), await alice.locator('#devices-view code.fingerprint').textContent());
  checks.push('Copy own device identity fingerprint');
  await alice.locator('.nav-item[data-view=chat]').click(); await alice.setViewportSize({ width: 390, height: 844 }); await alice.screenshot({ path: 'evidence/screenshots/chat-mobile.png', fullPage: true });
  assert.equal(await alice.evaluate(() => document.documentElement.scrollWidth > innerWidth), false); checks.push('390px mobile layout without horizontal overflow');
  await alice.setViewportSize({ width: 1440, height: 1000 });
  const diskRows = app.db.prepare('SELECT envelope FROM messages').all(); assert(!JSON.stringify(diskRows).includes('Hey Jamie')); assert(!JSON.stringify(diskRows).includes('project-notes.txt')); checks.push('Real browser messages and attachment filenames absent from SQLite rows');
  const storage = await alice.evaluate(() => JSON.stringify(localStorage)); assert(!storage.includes('Hey Jamie')); assert(!storage.includes('project-notes.txt')); assert(!storage.includes('privateKey')); checks.push('Browser persistence contains encrypted vault, no message plaintext');
  await bob.locator('.nav-item[data-view=devices]').click(); await bob.getByRole('button', { name: 'Rotate key', exact: true }).click(); await bob.getByRole('button', { name: 'Confirm', exact: true }).click(); await bob.getByText(/epoch 2/).waitFor();
  await bob.locator('.nav-item[data-view=chat]').click(); await bob.locator('.room-button').filter({ hasText: 'Design studio' }).click(); await bob.getByText(/This device has no key for this message/).first().waitFor();
  await alice.locator('#message-input').fill('New key epoch, same verified identity.'); await alice.locator('#send-button').click(); await bob.getByText('New key epoch, same verified identity.', { exact: true }).waitFor(); checks.push('Key rotation discards old epoch access and new messages decrypt successfully');
  await alice.locator('#new-room').click(); await alice.locator('#modal [name=name]').fill('Direct conversation'); await alice.locator('#modal [name=kind]').selectOption('direct'); await alice.getByText('@jamie.chen', { exact: true }).click(); await alice.getByRole('button', { name: 'Create encrypted channel' }).click();
  await bob.locator('.room-button').filter({ hasText: 'Direct conversation' }).click();
  const xss = '<img src=x onerror="window.chatInjection=true">'; await alice.locator('#message-input').fill(xss); await alice.locator('#send-button').click(); await bob.getByText(xss, { exact: true }).waitFor(); assert.equal(await bob.evaluate(() => window.chatInjection), undefined); checks.push('Direct messaging and HTML injection rendered as inert literal text');
  await alice.locator('.nav-item[data-view=security]').click(); await alice.getByRole('button', { name: 'Revoke access', exact: true }).click(); await alice.getByRole('button', { name: 'Confirm', exact: true }).click(); await bob.locator('#auth-screen').waitFor({ state: 'visible' }); checks.push('Administrator revocation immediately locks the connected recipient browser');
  assert.deepEqual(errors, []); checks.push('No uncaught browser JavaScript errors');
  const report = { generatedAt: new Date().toISOString(), browser: await browser.version(), checks, errors, status: 'passed' }; writeFileSync('evidence/browser.json', JSON.stringify(report, null, 2)); console.log(JSON.stringify(report, null, 2));
} catch (e) {
  await alice.screenshot({ path: 'evidence/screenshots/browser-failure.png', fullPage: true }); console.error(e); console.error('Browser errors:', errors); process.exitCode = 1;
} finally { await browser.close(); await app.close(); rmSync(directory, { recursive: true, force: true }); }
