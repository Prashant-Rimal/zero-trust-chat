# Threat model

## Assets

1. Message text, attachments, filenames, group names.
2. Private keys and ratchet state.
3. Account and device integrity (who can act as whom).
4. Group membership integrity (who can read a group).
5. Metadata: who talks to whom, when, how much.

## Adversaries

| | Adversary | Can | Cannot (by assumption) |
|---|---|---|---|
| A1 | Network attacker | Read and modify traffic outside TLS, replay requests | Break TLS |
| A2 | Outsider with an account | Call any API with their own valid session | Guess other users' secrets |
| A3 | Malicious or removed group member | Everything A2 can, plus they once held conversation keys | |
| A4 | Thief of one factor | Has a password, or a session cookie, or a TOTP seed — not all | |
| A5 | **Honest-but-curious server / database reader** | Read every table, log and backup | Modify data or code |
| A6 | **Actively malicious server** | Read and modify every table, forge directory and membership responses, drop or replay ciphertext | Break the cryptographic primitives; alter the JavaScript already running in an honest browser |
| A7 | Device thief | Copy the encrypted vault from disk | Know the password |

A compromised endpoint (malware, malicious extension, unlocked device in the wrong hands) and a server that ships altered client code are **out of scope**: both sit inside the trust boundary of any web-delivered E2EE system.

## Trust boundaries

- **Browser ↔ relay.** Everything the relay returns is treated as untrusted input by `messenger.ts`: directory entries are checked against pins, rosters against signatures, envelopes against the ratchet.
- **Relay ↔ database.** Parameterised SQL only. The relay holds one secret (`SERVER_SECRET`) that the database does not.

## Threats, mitigations and tests

Test names refer to `tests/*.test.ts`; each row was exercised, not just reasoned about.

### Impersonation

| Threat | Mitigation | Test |
|---|---|---|
| Stolen password (A4) | TOTP required; no session before it succeeds | *a password alone is not enough* |
| Intercepted TOTP code | Each time step accepted once per account | *a TOTP code cannot be used twice* |
| Password + TOTP seed stolen | New device starts **pending**: invisible to contacts, cannot read or send until an existing device cross-signs it; owner sees it on the dashboard | *a new device … starts as pending*, *a pending device is invisible to contacts* |
| Claiming an existing device id | Login requires a signature by that device's identity key; mismatch raises a high-severity event | *a device id cannot be claimed without its identity key* |
| Stolen session cookie (A1/A4) | HttpOnly + SameSite=Strict, CSRF token, Origin check; session bound to network and browser pseudonyms — both changing revokes it | *a stolen session cookie is useless…*, *a session cookie replayed from a different browser and network is revoked* |
| Forging the sender of a message (A2/A3) | Sender device comes from the session, never the request body; recipients authenticate via the pairwise ratchet | *the sender device is taken from the session*, *detects a forged sender device* |
| Password guessing | Rate limits per IP and per account; constant-shape error; brute-force signal | *throttles guessing*, *repeated failed sign-ins raise a brute-force signal* |
| Account enumeration | Same response and same work for unknown users; prefix-only user search | *rejects a wrong password without revealing…*, *usernames cannot be enumerated in bulk* |

### Key substitution (A6)

| Threat | Mitigation | Test |
|---|---|---|
| Replace a contact's identity key | Pinned per device id; a change blocks sending | *swapping a pinned identity key blocks sending* |
| Replace only the prekey | Prekeys must be signed by the pinned identity key | *swapping only the signed prekey fails…* |
| Upload a prekey for someone else's device | Server verifies the signature too | *the relay cannot register a prekey…* |
| Add a ghost device under a contact | Not cross-signed by a known device → verified status cleared, warning shown, security code no longer matches | *a ghost device injected under a contact…* |
| Forge the cross-signature | Must verify under a pinned key **of the same user** | *a device the account owner cross-signed is accepted…* (second half) |
| Answer a handshake as the recipient | Needs the recipient's private prekeys | *a relay that answers a handshake with its own keys…* |
| Substitute the sender's identity to the recipient | Identities are bound into the X3DH associated data; decryption fails | `protocol.test.ts`: *a responder handed a substituted sender identity…* |
| First contact, never verified | **Residual.** Trust on first use until security codes are compared | — |

### Unauthorised group access

| Threat | Mitigation | Test |
|---|---|---|
| Outsider reads or posts (A2) | Membership checked on directory, prekey bundle, send, upload, download; denials audited | *an outsider cannot list members, fetch keys, post, upload or download* |
| Member addresses ciphertext to an outside device | Recipient set must be trusted devices of members | *a member cannot address ciphertext to a device outside…* |
| Non-owner changes membership | Owner only, step-up required, roster signed by the owner's device | *only the owner can change membership…* |
| Removed member keeps reading (A3) | Clients stop encrypting to them at once; queued ciphertext for them is deleted | *a removed member stops receiving* |
| Server adds a member silently (A6) | Clients encrypt only to the owner-signed roster | *a member the relay adds behind the owner's back receives nothing* |
| Server rolls back to an old roster (A6) | Epoch pinned per conversation; sending blocked on rollback | *a rolled-back … roster is refused* |
| Admin reads conversations | No admin route touches messages; admins hold no keys | *administrators have no route to message content* |

### Content confidentiality and integrity (A5, A6)

| Threat | Mitigation | Test |
|---|---|---|
| Database or log reader recovers content | Only ciphertext stored; logs carry route patterns | *holds no plaintext, filename, group name, private key…*, *writes nothing sensitive to server logs* |
| Ciphertext modified | AEAD; failure is surfaced and state is untouched | *detects a modified ciphertext*, *keeps working after tampering* |
| Expiry extended, message moved or re-attributed | All envelope fields are associated data | *detects a modified expiry*, *…moved into another conversation* |
| Replay | Server tombstones + consumed keys | *the relay rejects a resubmitted message*, *a malicious relay re-delivering…* |
| Later key theft exposes history | Forward secrecy | `protocol.test.ts`: *gives forward secrecy* |
| Key theft exposes the future | Post-compromise recovery after a round trip | `protocol.test.ts`: *heals after compromise* |
| Vault copied from disk (A7) | Sealed with a 600k-iteration password-derived key | `protocol.test.ts`: *splits the password into unrelated auth and vault keys* |

### Session and device lifecycle

| Threat | Mitigation | Test |
|---|---|---|
| Revoked session keeps working | Checked per request and per socket frame; socket closed with 4001 | *ends a revoked session on the next request…*, *a socket frame from a session revoked after connecting…* |
| Delivery races revocation | Session re-verified immediately before each push | *no envelope is pushed to a socket whose session was revoked moments earlier* |
| Revoked device signs in again | Identity is permanently refused | *revoking a device ends its sessions…* |
| Compromised account | Admin revoke cuts all sessions and sockets | *revoking an account cuts off every session and socket* |
| Privilege escalation | Role checked per route; no self-service role change | RBAC suite |

### Metadata (A5)

Covered in [PRIVACY.md](PRIVACY.md) and the *metadata leakage* tests, which pin the database schema and the allowed audit fields so that a change which starts storing more fails CI.

### Web application

| Threat | Mitigation |
|---|---|
| XSS | React escaping; no `dangerouslySetInnerHTML`; QR codes drawn from a module matrix; CSP with per-request nonce, no `unsafe-eval`; attachments only ever downloaded as `application/octet-stream` |
| CSRF / cross-site WebSocket | SameSite=Strict, Origin check, CSRF header; Origin checked on upgrade |
| Injection | Parameterised SQL everywhere; strict schemas (`zod`, unknown fields rejected) |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| Resource exhaustion | Body size limits, WebSocket payload limit, per-route and per-session rate limits, bounded skipped-key store |

## Residual risks

1. **Server-delivered code.** The largest gap. Fix needs a client the server cannot silently change.
2. **First contact and unverified users** rely on the server's directory.
3. **Traffic analysis.** Sender, recipient, time and size class are visible to the server.
4. **Roster rollback against a brand-new member or device**, which has no earlier epoch to compare with.
5. **Denial of service by the server** (dropping messages) cannot be prevented, only noticed.
6. **`SERVER_SECRET` + database together** reveal TOTP seeds (not messages, not vault keys).
7. **In-memory rate limits** reset on restart and are per instance.
8. **Password quality** is the only protection for a stolen vault file.
