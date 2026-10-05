# Threat model

Scope: this local prototype, its browser client, relay and SQLite storage. All demonstrations use synthetic accounts on loopback. Attacker classes: unauthenticated network client, malicious authenticated member, revoked device, stolen session, passive database reader, active relay, compromised endpoint.

| Priority / risk | Attack and trust boundary | Mitigation and test | Residual risk |
|---|---|---|---|
| P0 / High: account impersonation | Password theft or guessed MFA at identity boundary | Mandatory TOTP, scrypt, rate limits, one-use challenges/codes; RFC vector and replay tests | Phishing, stolen TOTP seed, endpoint compromise; no hardware-backed MFA |
| P0 / High: group access bypass | Member requests another group's messages/keys | Membership checked at reads, writes and live delivery; outsider tests | Relay knows membership; active relay can lie about new identities |
| P0 / High: key substitution | Relay swaps encryption key under a valid identity | Identity-signed exchange certificate; browser verifies, pins signing key and highest epoch; mutation tests | First-contact/new-device substitution needs independent fingerprint verification |
| P0 / High: plaintext database breach | Copy SQLite contents | Browser AEAD payloads/wrapped keys; plaintext sentinel and filename absence assertions | Metadata remains visible; server master key exposes MFA seeds if stolen too |
| P0 / High: stolen session/device | Reuse cookie after administrator response | Device/account/session revocation; per-request and delivery checks; immediate socket close | Already received plaintext cannot be recalled |
| P1 / High: XSS / malicious client delivery | Execute code inside endpoint trust boundary | Static script allowlist, CSP without inline/eval, textContent rendering, octet-stream download | Server can replace original JS; extensions/OS can read keys and content |
| P1 / Medium: envelope tampering / impersonation | Alter sender, room, expiry, ciphertext | AES-GCM AAD + ECDSA whole-envelope signature; mutation tests | Custom protocol not externally audited |
| P1 / Medium: replay | Resubmit valid old envelope | Signed UUID + persistent tombstones; 409 and audit event; expiry replay tests | Relay/recipient metadata remains observable |
| P1 / Medium: CSRF / cross-site WebSocket | Attacker origin drives privileged actions | SameSite cookie, exact origin, CSRF token, handshake origin validation | Browser compromise bypasses this layer |
| P1 / Medium: injection / traversal | SQL metacharacters, dynamic paths or HTML in chat | Parameterized SQL; static route map; literal DOM text; negative API/browser tests | No generic WAF or comprehensive fuzzing |
| P1 / Medium: MFA replay | Reuse code in a second challenge | Persist last accepted time step, reject same/older counter | Device clock skew may lock out legitimate user temporarily |
| P1 / Medium: denial of service | Expensive password work / large bodies / open sockets | IP/account/session limits; 3.2 MB request bound; timeouts; WS limits | Single-process in-memory limits reset on restart; no cluster-scale defense |
| P2 / Medium: metadata leakage | Observe times, recipient set, sizes, channel names | No analytics, no read receipts, minimal audit, retention; explicit privacy view | No mixnet, padding, sealed sender, DP or traffic-analysis resistance |
| P2 / Medium: historical key compromise | Recover old epoch key/backup | Manual epoch rotation removes active previous key; history-loss test | Not full per-message forward secrecy; backups can defeat deletion |

## OWASP categories actually exercised

- **Broken Access Control:** outsider group reads, non-admin account revocation, cross-account device/session boundaries and stale step-up.
- **Cryptographic Failures:** AEAD tampering, forged signing identity, key substitution, encrypted vault wrong password, plaintext persistence checks.
- **Injection:** SQL-like login input, textContent-based client rendering, static policy checks on DOM sinks.
- **Identification and Authentication Failures:** invalid credentials, MFA counter replay, expired/revoked sessions.
- **Security Logging and Monitoring Failures:** replay/tampering produce auditable signals; revocation incident checks containment.

## Accepted / deferred

No claim of anonymous membership, differential privacy, hardware device posture, transparent key directory, denial-of-service resilience at internet scale, guaranteed secure erase, self-healing accounts, production secret management or a formally proven E2EE protocol. These are explicit next-stage risks, not scanner-confirmed vulnerabilities silently marked fixed.
