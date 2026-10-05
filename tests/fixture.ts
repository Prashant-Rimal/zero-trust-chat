import { randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { Readable } from 'node:stream'
import { createApp } from '~/server/app'
import type { App } from '~/server/app'
import { migrate, openPglite } from '~/server/db'
import { handleUpgrade } from '~/server/realtime'

/** The relay behind a real Node HTTP server with the production WebSocket binding, on a random local port. */
export async function startServer() {
  const db = await openPglite()
  await migrate(db)
  let app!: App
  let base = ''
  const server = createServer(async (req, res) => {
    const body = req.method === 'GET' ? undefined : (Readable.toWeb(req) as ReadableStream)
    const request = new Request(base + req.url, { method: req.method, headers: req.headers as HeadersInit, body, duplex: 'half' } as RequestInit)
    const response = await app.handle(request, { ip: req.socket.remoteAddress ?? '' })
    res.writeHead(response.status, [...response.headers])
    res.end(Buffer.from(await response.arrayBuffer()))
  })
  server.on('upgrade', (req, socket, head) => void handleUpgrade(req, socket, head))
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  app = createApp({ db, secret: randomBytes(32), origin: base, log: () => {} })
  const globals = globalThis as any
  // The WebSocket binding resolves the relay through the process-wide singleton.
  globals.__cipherroom = Promise.resolve(app)
  return {
    base,
    app,
    db,
    async close() {
      for (const client of globals.__cipherroomWss?.clients ?? []) client.terminate()
      globals.__cipherroomWss?.close()
      delete globals.__cipherroom
      delete globals.__cipherroomWss
      await new Promise((resolve) => server.close(resolve))
      await db.close()
    },
  }
}
