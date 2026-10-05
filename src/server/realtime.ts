/**
 * Binds the relay's realtime hub to WebSocket upgrades on a Node HTTP server.
 * Used by the Vite dev server (through a plugin) and by the production entry (serve.mjs).
 */
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'
import { WebSocketServer } from 'ws'
import type { WebSocket } from 'ws'
import { clientIp, getApp } from './runtime'

const globals = globalThis as { __cipherroomWss?: WebSocketServer }

function server() {
  if (globals.__cipherroomWss) return globals.__cipherroomWss
  const wss = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024, perMessageDeflate: false })
  const timer = setInterval(async () => {
    for (const ws of wss.clients) ws.ping()
    // Only touch the database while someone is connected, so an idle deployment can scale to zero.
    if (wss.clients.size) (await getApp()).sweep(true).catch(() => {})
  }, 30_000)
  timer.unref()
  return (globals.__cipherroomWss = wss)
}

const reject = (socket: Duplex, status: string) => {
  socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`)
  socket.destroy()
}

export async function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer) {
  try {
    const app = await getApp()
    let ws: WebSocket | undefined
    const connection = await app.realtime.connect(
      {
        cookie: req.headers.cookie ?? null,
        origin: req.headers.origin ?? null,
        ip: clientIp(req.socket.remoteAddress, req.headers['x-forwarded-for']?.toString()),
        agent: req.headers['user-agent'] ?? '',
      },
      { send: (data) => ws?.send(data), close: (code, reason) => ws?.close(code, reason) },
    )
    server().handleUpgrade(req, socket, head, (opened) => {
      ws = opened
      ws.on('error', () => {})
      ws.on('close', connection.close)
      ws.on('message', (data, isBinary) => {
        if (isBinary) return ws!.close(1003, 'Text frames only')
        void connection.message(data.toString())
      })
      ws.send(JSON.stringify({ t: 'ready' }))
    })
  } catch (error) {
    const status = (error as { status?: number }).status
    reject(socket, status === 401 ? '401 Unauthorized' : status === 429 ? '429 Too Many Requests' : '403 Forbidden')
  }
}
