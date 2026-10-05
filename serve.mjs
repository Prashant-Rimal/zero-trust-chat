/**
 * Production entry: one long-running Node process serving the built TanStack Start app,
 * its static assets, and the WebSocket endpoint.
 *
 *   npm run build && npm start
 */
import { createReadStream, existsSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize, resolve } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'

process.env.NODE_ENV ??= 'production'
const port = Number(process.env.PORT ?? 3000)
// Must be set before the app boots: it is what Origin headers and WebSocket upgrades are checked against.
process.env.APP_ORIGIN ??= `http://localhost:${port}`
const root = fileURLToPath(new URL('./dist/', import.meta.url))
const clientDir = resolve(root, 'client')
const { default: app } = await import(new URL('./dist/server/server.js', import.meta.url).href)
const upgrade = globalThis.__cipherroomUpgrade
// Fail at startup, not on the first request, if configuration or the database is wrong. Also runs migrations.
await globalThis.__cipherroomBoot()

const TYPES = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.woff2': 'font/woff2', '.map': 'application/json', '.txt': 'text/plain; charset=utf-8', '.webmanifest': 'application/manifest+json' }

function staticFile(pathname) {
  if (pathname === '/' || pathname.includes('\0')) return null
  const file = normalize(join(clientDir, decodeURIComponent(pathname)))
  if (!file.startsWith(clientDir) || !existsSync(file) || !statSync(file).isFile()) return null
  return file
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const file = req.method === 'GET' || req.method === 'HEAD' ? staticFile(url.pathname) : null
    if (file) {
      res.writeHead(200, {
        'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream',
        'Content-Length': statSync(file).size,
        'X-Content-Type-Options': 'nosniff',
        // Vite fingerprints everything under /assets, so it can be cached forever.
        'Cache-Control': url.pathname.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache',
      })
      return req.method === 'HEAD' ? res.end() : createReadStream(file).pipe(res)
    }
    const hasBody = req.method !== 'GET' && req.method !== 'HEAD'
    const request = new Request(url, { method: req.method, headers: req.headers, body: hasBody ? Readable.toWeb(req) : undefined, duplex: 'half' })
    // The relay reads the peer address from here; with TRUST_PROXY=1 it uses the proxy-appended X-Forwarded-For entry instead.
    Object.defineProperty(request, 'ip', { value: req.socket.remoteAddress })
    const response = await app.fetch(request)
    res.writeHead(response.status, [...response.headers])
    if (!response.body || req.method === 'HEAD') return res.end()
    Readable.fromWeb(response.body).pipe(res)
  } catch {
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' })
    res.end('Internal error')
  }
})
server.requestTimeout = 30_000
server.headersTimeout = 10_000
server.on('upgrade', (req, socket, head) => {
  if (new URL(req.url ?? '/', 'http://localhost').pathname !== '/ws' || !upgrade) return socket.destroy()
  void upgrade(req, socket, head)
})


const host = process.env.HOST ?? '0.0.0.0'
server.listen(port, host, () => console.log(JSON.stringify({ event: 'listening', host, port, origin: process.env.APP_ORIGIN ?? `http://localhost:${port}` })))
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)))
