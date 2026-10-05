/**
 * TanStack Start server entry. Wraps the default handler to add security headers and a
 * per-request CSP nonce, and exposes the WebSocket upgrade handler to the production entry.
 */
import { randomBytes } from 'node:crypto'
import handler from '@tanstack/react-start/server-entry'
import { handleUpgrade } from './server/realtime'
import { config, getApp } from './server/runtime'

// The production entry (serve.mjs) picks these up after importing the built bundle.
Object.assign(globalThis, { __cipherroomUpgrade: handleUpgrade, __cipherroomBoot: getApp })

function secure(response: Response, nonce: string) {
  const c = config()
  const headers = new Headers(response.headers)
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('Referrer-Policy', 'no-referrer')
  headers.set('X-Frame-Options', 'DENY')
  headers.set('Cross-Origin-Opener-Policy', 'same-origin')
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  if (c.origin.startsWith('https://')) headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  // Vite's dev server injects inline module scripts and styles, so the strict policy is production-only.
  if (c.production) {
    const ws = c.origin.replace(/^http/, 'ws')
    headers.set(
      'Content-Security-Policy',
      [
        `default-src 'self'`,
        `script-src 'self' 'nonce-${nonce}'`,
        `style-src 'self' 'unsafe-inline'`,
        `img-src 'self' data: blob:`,
        `connect-src 'self' ${ws}`,
        `object-src 'none'`,
        `base-uri 'none'`,
        `frame-ancestors 'none'`,
        `form-action 'self'`,
      ].join('; '),
    )
  }
  if ((headers.get('content-type') ?? '').includes('text/html')) headers.set('Cache-Control', 'no-store')
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

export default {
  async fetch(request: Request) {
    const nonce = randomBytes(16).toString('base64')
    return secure(await handler.fetch(request, { context: { nonce } }), nonce)
  },
}
