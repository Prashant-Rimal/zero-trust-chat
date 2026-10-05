/**
 * Deployment smoke test: runs two headless clients against a live server over real HTTP and
 * WebSocket.  TARGET_URL=https://your-deployment npm run smoke
 *
 * Optional: PEER=<username> also messages that (already registered) user and waits for a reply,
 * which is handy for checking a browser session by hand.
 */
import { expect, it } from 'vitest'
import { LiveClient } from './live'

const base = (process.env.TARGET_URL ?? 'http://localhost:3000').replace(/\/$/, '')
const suffix = Date.now().toString(36).slice(-6)

it(`serves the app shell with security headers at ${base}`, async () => {
  const response = await fetch(base)
  expect(response.status).toBe(200)
  expect(await response.text()).toContain('Cipherroom')
  expect(response.headers.get('x-content-type-options')).toBe('nosniff')
  expect(response.headers.get('x-frame-options')).toBe('DENY')
})

it('registers two accounts, exchanges encrypted messages and an attachment in real time', async () => {
  const a = await new LiveClient(base, `smoke_a_${suffix}`).register()
  const b = await new LiveClient(base, `smoke_b_${suffix}`).register()
  await a.connect()
  await b.connect()
  const conv = await a.messenger.createConversation('direct', [b.me.user.id])
  await a.messenger.send(conv, 'smoke: hello', { lifetimeSeconds: 300 })
  await b.until(() => b.texts(conv).includes('smoke: hello'), 15_000)
  await b.messenger.send(conv, 'smoke: reply', { lifetimeSeconds: 300, file: { name: 'smoke.bin', type: 'application/octet-stream', bytes: new Uint8Array(4096).fill(7) } })
  await a.until(() => a.texts(conv).includes('smoke: reply'), 15_000)
  const file = a.messenger.messages(conv).find((m) => m.file)!.file!
  expect(await a.messenger.openAttachment(conv, file)).toEqual(new Uint8Array(4096).fill(7))
  expect((await new LiveClient(base, 'nobody').fetch('GET', '/api/conversations')).status).toBe(401)
  await a.api('POST', '/api/auth/logout', {})
  await b.api('POST', '/api/auth/logout', {})
})

it.runIf(process.env.PEER)('chats with a signed-in browser user', async () => {
  const bot = await new LiveClient(base, `bot_${suffix}`).register()
  await bot.connect()
  const [peer] = await bot.messenger.searchUsers(process.env.PEER!)
  expect(peer, `user ${process.env.PEER} not found`).toBeTruthy()
  const conv = await bot.messenger.createConversation('direct', [peer.id])
  await bot.messenger.send(conv, 'Hello from the headless client. Reply to me and I will confirm I could decrypt it.')
  console.log(`bot ${bot.username} verification code: ${bot.messenger.verificationCode()}`)
  await bot.until(() => bot.texts(conv).length > 1, Number(process.env.WAIT_MS ?? 120_000))
  await bot.messenger.send(conv, `Decrypted your reply: “${bot.texts(conv).at(-1)}”`)
  if (process.env.GROUP) {
    const group = await bot.messenger.createConversation('group', [peer.id], process.env.GROUP)
    await bot.messenger.send(group, 'Welcome to the group. Its name reached you inside an encrypted message.')
  }
  await new Promise((resolve) => setTimeout(resolve, 1500))
})
