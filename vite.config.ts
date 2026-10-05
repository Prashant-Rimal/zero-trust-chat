import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import viteReact from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import type { Plugin } from 'vite'

/** In development the WebSocket endpoint rides on Vite's own HTTP server. */
function realtimeDev(): Plugin {
  return {
    name: 'cipherroom-realtime-dev',
    configureServer(server) {
      // Origin checks need the real dev origin; follow whatever port Vite was given.
      process.env.APP_ORIGIN ??= `http://localhost:${server.config.server.port ?? 3000}`
      server.httpServer?.on('upgrade', async (req, socket, head) => {
        if (new URL(req.url ?? '/', 'http://localhost').pathname !== '/ws') return
        try {
          const realtime = await server.ssrLoadModule('/src/server/realtime.ts')
          await realtime.handleUpgrade(req, socket, head)
        } catch {
          socket.destroy()
        }
      })
    },
  }
}

// Vite only exposes .env to client code. The relay reads process.env, so copy the server settings across.
for (const [name, value] of Object.entries(loadEnv('development', process.cwd(), ''))) {
  if (/^(DATABASE_URL|SERVER_SECRET|APP_ORIGIN|TRUST_PROXY|DP_EPSILON|DP_WINDOW_MINUTES|DATA_DIR)$/.test(name) && value) process.env[name] ??= value
}

export default defineConfig({
  resolve: { alias: { '~': fileURLToPath(new URL('./src', import.meta.url)) } },
  // PGlite ships a WASM Postgres and must be loaded from node_modules at runtime, not bundled.
  ssr: { external: ['@electric-sql/pglite', 'pg', 'ws'] },
  plugins: [tailwindcss(), tanstackStart(), viteReact(), realtimeDev()],
})
