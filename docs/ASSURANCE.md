# Assurance: what was tested and measured

## How the tests are built

- `npm test` runs 102 tests in about six seconds with no external services (in-process Postgres via PGlite).
- The tests use the **real client engine** (`src/client/messenger.ts`) against the **real relay** (`src/server/app.ts`). There is no mock crypto and no mock server.
- Where the adversary is the server or database, the test **edits the database directly** (swaps a key, inserts a member, rewrites a ciphertext) and checks what honest clients do.
- `tests/transport.test.ts` adds real HTTP and WebSocket sockets through the production WebSocket binding.
- Only `Date` is faked, to advance TOTP steps and expiries without waiting.
- Setting `TEST_DATABASE_URL` runs the same suite against real Postgres/Neon.

| File | Tests | Covers |
|---|---|---|
| `tests/protocol.test.ts` | 18 | X3DH, Double Ratchet, forward secrecy, post-compromise recovery, tamper/replay at protocol level, rosters, fingerprints, padding, attachments, vault |
| `tests/e2ee.test.ts` | 18 | Delivery; server cannot read; logs; replay; tampering; ephemeral messages |
| `tests/threats.test.ts` | 26 | Impersonation, key substitution, unauthorised group access, metadata leakage |
| `tests/zerotrust.test.ts` | 25 | Policy table, device trust, continuous verification, revocation, realtime, RBAC |
| `tests/dp.test.ts` | 10 | Laplace mechanism, clipping, single release, deletion |
| `tests/transport.test.ts` | 5 | Real sockets: upgrade refusal, live delivery, attachments, revocation closes socket, malformed frames |

## Required validation

### The server and database cannot read protected content

*`e2ee.test.ts` → "the server and database cannot read protected content"*

After real messages, a group rename and an attachment upload, the test dumps **every row of every table** and asserts that none of the following appear, raw or base64-encoded: message text, attachment body, attachment filename, group name. It also asserts the dump contains no device private key (identity, DH, signed prekey, one-time prekeys), no login key, no TOTP seed and no client IP. The same sentinels, plus the session cookie, CSRF token, usernames and all ids, are checked against captured server logs.

The dump is confirmed to contain live `envelopes` and `attachments` rows, so the test is not passing on an empty database.

### Replay

- Resubmitting a stored message to the relay → `409 replay` and a `message.replay_blocked` event, including after the original has been delivered and deleted.
- A relay re-delivering a captured envelope to the recipient → discarded, shown once.
- The same envelope under a new message id → fails authentication (the id is in the associated data).
- Timestamps outside ±2 minutes → refused.

### Tampering

With the ciphertext row rewritten in the database before delivery: modified ciphertext, extended expiry, different conversation, different sender device, modified attachment bytes. In every case the recipient shows nothing, records a warning, and the **next genuine message still decrypts** — a failed decryption does not corrupt ratchet state.

### Session revocation

- Revoked session → next HTTP request is 401; live WebSocket is closed with code 4001.
- A frame arriving on a socket whose session was revoked after connecting is refused and the socket closed.
- A message sent just after a recipient's session is revoked is **not** pushed to that socket.
- Device revocation → sessions ended, device excluded from future fan-out, identity can never sign in again.
- Admin account revocation → all sessions and sockets ended, sign-in refused, restorable.
- Idle timeout (30 min), absolute lifetime (8 h), sign-out.

### Threat-model-based tests

See [THREAT-MODEL.md](THREAT-MODEL.md) for the mapping of each threat to a named test: impersonation (9 tests), key substitution (6 + 4 at protocol level), unauthorised group access (7), metadata leakage (4).

## Encryption and latency overhead

`npm run benchmark` → `evidence/benchmark.json`. Figures below are medians (p50) from one run on an AMD Ryzen 9 7950X, Node 24, loopback network, in-process database. They show **relative** cost; they are not capacity numbers, and browsers on phones will be several times slower.

### One-off costs

| Operation | Time |
|---|---|
| Password key derivation (PBKDF2, 600k iterations), once per unlock | 65 ms |
| Generate a device's keys | 1.4 ms |
| Start a session with a new device (X3DH: 2 signature checks, 3–4 DH) | 5.3 ms |
| Compute a security code (5,200 hash iterations) | 3.3 ms |

### Per message

| Plaintext | Encrypt | Decrypt | On the wire | Expansion |
|---|---|---|---|---|
| 32 B | 0.028 ms | 0.023 ms | 796 B | 24.9× |
| 256 B | 0.033 ms | 0.024 ms | 1,136 B | 4.4× |
| 1 KB | 0.048 ms | 0.028 ms | 2,160 B | 2.1× |
| 8 KB | 0.201 ms | 0.069 ms | 11,720 B | 1.4× |

A reply that turns the DH ratchet (new key pair + two DH operations) costs about 1.9 ms per side.

The size overhead for short messages is deliberate: 256-byte padding hides length, and the envelope carries ids, a ratchet header and base64 encoding. It is paid once per recipient device.

### Group fan-out (encrypt one 200-byte message for N devices)

| Recipient devices | Encrypt time |
|---|---|
| 1 | 0.03 ms |
| 5 | 0.15 ms |
| 10 | 0.29 ms |
| 25 | 0.74 ms |
| 50 | 1.46 ms |

Linear, about 0.03 ms per device. Bandwidth, not CPU, is what limits pairwise fan-out for very large groups.

### Attachments

About 125 MB/s for encrypt and for decrypt-and-verify (XChaCha20-Poly1305 in JavaScript); a 4 MB file takes about 31 ms. Size overhead is a constant 16 bytes.

### End-to-end latency (real HTTP + WebSocket, loopback)

| Measurement | p50 | p95 |
|---|---|---|
| Send → recipient has decrypted and stored the message | 3.76 ms | 4.80 ms |
| Client-side work before the network (directory check, encrypt, persist) | 0.07 ms | 0.10 ms |
| Send → server confirmation | 3.59 ms | 4.63 ms |
| **Baseline:** same relay hop with a pre-built envelope (no client crypto in the timed section) | 3.34 ms | 4.06 ms |

Cryptography accounts for roughly **2 %** of end-to-end latency on an established session. The relay's own work — re-authenticating the session, checking membership and recipient devices, and writing the replay tombstone and ciphertext in a transaction — dominates. That is the cost of continuous verification, and on a real network both are dwarfed by round-trip time.

## Manual checks performed

- Development server and production build each driven in a browser: account creation with TOTP QR, sign-in, vault unlock after reload, live message exchange with a headless peer, group with encrypted name, step-up prompt and retry, admin role change, devices and security pages.
- Production build served with the strict Content-Security-Policy: inline hydration scripts carry the per-request nonce; no console errors.
- `npm run smoke` passes against both the dev server and the production build.

## Not yet verified

- **The Neon / `pg` code path has not been run.** All tests ran on PGlite. The SQL is the same and PGlite is real Postgres, but connection handling, TLS and type parsing under `pg` are unexercised until the suite is run with `TEST_DATABASE_URL`.
- Device approval and two-person chats were verified by the automated suite, not by hand in two browsers.
- No fuzzing, no load test, no third-party review, no formal analysis of the protocol composition.
- Layouts were built responsively but checked at one desktop-sized viewport only; phone widths are unverified.
