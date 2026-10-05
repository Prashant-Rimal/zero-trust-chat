import { createFileRoute } from '@tanstack/react-router'
import { clientIp, getApp } from '~/server/runtime'

/** Every /api/* request is handed to the relay, which does its own routing, authentication and policy checks. */
async function relay({ request }: { request: Request }) {
  const app = await getApp()
  const peer = (request as { ip?: string }).ip
  return app.handle(request, { ip: clientIp(peer, request.headers.get('x-forwarded-for')) })
}

export const Route = createFileRoute('/api/$')({
  server: { handlers: { GET: relay, POST: relay, PUT: relay, DELETE: relay } },
})
