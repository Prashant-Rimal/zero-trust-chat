import { createRouter } from '@tanstack/react-router'
import { getGlobalStartContext } from '@tanstack/react-start'
import { routeTree } from './routeTree.gen'

/** The per-request CSP nonce set in src/server.ts, so the inline hydration scripts are allowed to run. */
function requestNonce() {
  try {
    return (getGlobalStartContext() as { nonce?: string } | undefined)?.nonce
  } catch {
    return undefined
  }
}

export function getRouter() {
  return createRouter({ routeTree, scrollRestoration: true, defaultPreload: false, ssr: { nonce: requestNonce() } })
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>
  }
}
