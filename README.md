# Cipherroom

Real-time messaging where the server relays ciphertext it cannot read. Built on **TanStack Start** (React 19, Vite), **Postgres** (Neon in production, in-process PGlite for development and tests) and **WebSockets**.

> Coursework prototype. It uses reviewed primitives (`@noble/*`) in a Signal-style design, but the composition has not been independently audited. Do not use it to protect real secrets.

## What it does

| Requirement | How | Where |
|---|---|---|
| Secure authentication, 2FA | Password-derived login key (the password itself never leaves the browser), TOTP, and a signature from the device identity key | `src/server/app.ts`, `src/shared/protocol.ts` |
| RBAC for admin functions | `member` / `auditor` / `admin` with a per-route permission table | `ROLE_PERMISSIONS` in `src/server/app.ts` |
| End-to-end encryption, key exchange | X3DH (signed + one-time prekeys) → Double Ratchet, XChaCha20-Poly1305 | `src/shared/protocol.ts` |
| Key rotation, forward secrecy | New key per message; DH ratchet on every reply; signed prekey rotated weekly or on demand | `ratchetEncrypt` / `ratchetDecrypt` |
| Fingerprint / QR verification | 60-digit security code per pair, QR code, paste-to-verify | Chat → Details, Devices page |
| One-to-one and group channels over WebSocket | Per-device fan-out; group membership is a roster signed by the owner | `src/client/messenger.ts`, `src/server/realtime.ts` |
| Encrypted attachments and storage | Files encrypted in the browser; server stores ciphertext until delivery; local history sealed in IndexedDB | `encryptAttachment`, `src/client/session.ts` |
| No plaintext in logs | Logs carry route patterns and status only | `handle()` in `src/server/app.ts` |
| Ephemeral messages, integrity, replay protection | Expiry authenticated inside the AEAD; replay tombstones server-side, consumed keys client-side | `tests/e2ee.test.ts` |
| Device and session management | Pending → trusted → revoked devices, remote session end | Devices page |
| Security dashboard | Login anomalies, session context changes, key changes, revocation | Security and Admin pages |
| Metadata minimisation | See [docs/PRIVACY.md](docs/PRIVACY.md) and the in-app Privacy page | |
| **Advanced: Zero Trust** | Every request and socket frame re-evaluates session, device and account; new devices need cross-signed approval; step-up for sensitive actions; risk-based session revocation | `authenticate()` / `authorize()` |
| **Advanced: Differential privacy** | Per-user clipping, Laplace noise, one release per period, raw rows deleted | `src/server/dp.ts` |

## Run it

Requires Node 22.12+ (developed on Node 24). No database or Docker needed locally.

```bash
npm install
```

```bash
npm run dev
```

Open http://localhost:3000. The first account to finish two-factor setup becomes the workspace administrator.

**Trying it with two people on one computer:** sessions and key vaults are per browser profile, so use two different browsers, or one normal window and one private window. A second *tab* in the same profile is the same person.

**Adding a second device to an account:** sign in from another browser profile. It shows a short code and waits; approve it from the first browser under Devices.

## Verify it

```bash
npm test
```

102 tests, about six seconds, no external services. They drive the real client engine against the real relay and include tests where the "attacker" edits the database directly. See [docs/ASSURANCE.md](docs/ASSURANCE.md).

```bash
npm run benchmark
```

Measures encryption and latency overhead and writes `evidence/benchmark.json`.

```bash
npm run build
```

```bash
npm start
```

Runs the production build as a single Node process (HTTP + WebSocket). In production `SERVER_SECRET` is required; see [.env.example](.env.example).

```bash
npm run smoke
```

Runs two headless clients against a live server over real HTTP and WebSocket. Set `TARGET_URL` to test a deployment.

## Layout

```
src/shared/protocol.ts   Cryptographic protocol. No I/O. Runs in the browser and in Node.
src/client/messenger.ts  Client engine: sessions, pins, rosters, send/receive. No DOM.
src/client/session.ts    Browser glue: IndexedDB vault, fetch + WebSocket, sign-in flow.
src/server/app.ts        The relay: routes, policy table, session checks, realtime hub.
src/server/dp.ts         Differentially private analytics.
src/server/db.ts         Postgres schema and the pg / PGlite adapters.
src/server/realtime.ts   WebSocket binding for Node.
src/routes/              TanStack Start routes (UI pages and the /api catch-all).
serve.mjs                Production entry.
tests/                   Security tests, benchmark, smoke test.
docs/                    Architecture, protocol, threat model, privacy, assurance, deployment.
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol and key lifecycle](docs/PROTOCOL.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Privacy: what the server sees, and differential privacy](docs/PRIVACY.md)
- [Assurance: tests and measurements](docs/ASSURANCE.md)
- [Deployment (Neon, CI)](docs/DEPLOYMENT.md)

## Known limits

- The server delivers the JavaScript. A malicious operator could serve a modified client. This is inherent to web-delivered E2EE.
- First contact trusts the server's key directory until two people compare security codes.
- No sealed sender, cover traffic or anonymous routing: the server sees who talks to whom and when.
- A device that joins later does not receive earlier history.
- Rate limits and the realtime hub are in-memory, so the app runs as a single instance.
- Forgetting the password loses the local key vault; there is no account recovery beyond an admin device reset.
