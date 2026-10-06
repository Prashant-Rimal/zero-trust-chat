# Architecture

## Components

```
 Browser (trusted)                         Relay (untrusted for content)            Postgres
┌────────────────────────────┐            ┌───────────────────────────────┐       ┌────────────────┐
│ React UI (TanStack Router) │            │ TanStack Start server entry   │       │ users, devices │
│ session.ts  ── IndexedDB   │  HTTPS     │  ├ SSR shell + CSP nonce      │       │ prekeys        │
│   vault sealed with        │──────────▶ │  └ /api/$ → app.handle()      │ ────▶ │ sessions       │
│   password-derived key     │            │       policy table            │       │ conversations  │
│ messenger.ts               │  WSS /ws   │       authenticate/authorize  │       │ members        │
│   X3DH, Double Ratchet,    │◀──────────▶│  realtime hub                 │       │ envelopes (ct) │
│   pins, signed rosters     │            │       re-checks session on    │       │ attachments(ct)│
│ protocol.ts (noble)        │            │       every frame + delivery  │       │ replays, audit │
└────────────────────────────┘            └───────────────────────────────┘       │ usage_*        │
                                                                                  └────────────────┘
```

The split that matters: `src/shared/protocol.ts` and `src/client/messenger.ts` hold every key and every plaintext and never import server code. `src/server/app.ts` never imports client code and has no function that takes plaintext.

## Why these choices

**TanStack Start.** File routes give the UI; one catch-all server route (`src/routes/api/$.ts`) hands `/api/*` to the relay. The relay is a plain `handle(Request) → Response` function, so the test suite calls it directly without a framework or a port. A custom server entry (`src/server.ts`) adds security headers and a per-request CSP nonce.

**WebSockets beside Start.** Start has no built-in WebSocket story, so `src/server/realtime.ts` attaches a `ws` server to the HTTP `upgrade` event. In development a small Vite plugin does the attaching; in production `serve.mjs` does. Both call the same `app.realtime.connect()`.

**Postgres through a thin adapter.** `src/server/db.ts` exposes `query` and `tx` over either `pg` (Neon) or PGlite (in-process Postgres compiled to WASM). Same SQL, same schema. Development and CI need no database server.

**Pairwise fan-out for groups, not sender keys.** A group message is encrypted separately for each recipient device over its own Double Ratchet session. It costs about 0.03 ms per device (see ASSURANCE) and gives groups the same forward secrecy and post-compromise recovery as one-to-one chats. Removing a member takes effect immediately with no group re-key.

**Local history.** Double Ratchet keys are deleted after use, so the server copy of a message cannot be decrypted twice. Each device keeps its own history, sealed with the vault key, and the server deletes ciphertext as soon as the recipient device acknowledges it.

## Request lifecycle

Every non-public route declares a policy:

```ts
route('POST', '/api/devices/:id/approve', { access: 'trusted', stepUp: true, body: schema }, handler)
```

`handle()` then runs, in order: route match → Origin check (non-GET) → `authenticate` (session valid, not idle, not expired, account active, device not revoked, context unchanged) → CSRF token → rate limit → `authorize` (device trust level, role permission, step-up freshness) → body size limit and schema validation → handler. Nothing is cached between requests. WebSocket frames go through the same `authenticate` and `authorize`.

## Sign-in

1. Browser derives `master = PBKDF2(password, salt = H(username), 600k)`, then `authKey` and `vaultKey` by HKDF with different labels.
2. `authKey` goes to the server, which stores `scrypt(authKey)`. `vaultKey` unseals the IndexedDB vault and never leaves the device.
3. Server returns a single-use challenge. Browser sends the TOTP code, the device's public keys, and an Ed25519 signature over the challenge.
4. Server sets an HttpOnly, SameSite=Strict session cookie (only its SHA-256 is stored) and returns a CSRF token.

A page reload clears the vault key from memory. To survive it, the key is kept wrapped under a non-extractable WebCrypto key: the wrapping key sits in IndexedDB, the wrapped copy in the tab's `sessionStorage`. On load, if the server session is still valid for that device, the vault reopens without a prompt. Signing out, a revoked or expired session, or closing the tab discards the wrapped copy; then, if the server session is still valid, the password alone unlocks the vault, otherwise the full flow runs.

## Realtime

Server → client frames: `envelope` (ciphertext for this device), `sync` (conversations / devices / security changed — refetch), `sent` (result of a send).
Client → server frames: `send`, `ack`, `ping`.

Before each push the hub runs one query to confirm every target socket's session is still alive; dead ones are closed with code 4001 instead of receiving the frame.

## Scaling notes

Rate limits and the hub live in process memory, so run one instance. Going multi-instance needs a shared limiter and a pub/sub channel (Postgres `LISTEN/NOTIFY` on a direct, non-pooled connection would do). The database schema needs no change.
