# Security assurance and evidence

This is reproducible prototype evidence, not an external penetration-test certification. All attack cases target synthetic loopback accounts and temporary SQLite databases. The real local app's data is not touched by test scripts.

## Executed techniques

1. **Adversarial protocol/API testing:** Node test runner, actual HTTP and WebSocket requests; saved in `evidence/tests.tap`.
2. **Browser-based dynamic testing:** Playwright/Chrome, two isolated browser contexts, real WebCrypto, MFA enrollment, group/direct messaging, encrypted files, literal HTML injection, key rotation and admin revocation; `evidence/browser.json` and screenshots.
3. **Static/security/secret policy checks:** focused source scan for dynamic execution, logging sensitive requests, dynamic DOM sinks, private key markers and cloud key formats; `evidence/static-scan.json`. This is intentionally limited, not equivalent to a broad commercial SAST engine.
4. **Dependency vulnerability analysis:** npm audit against installed lockfile; `evidence/dependency-audit.json`. Zero advisories at execution time is not proof that dependencies contain no vulnerabilities.
5. **Measurement:** 40-message encryption/decryption benchmark and loopback delivery measurement; `evidence/benchmark.json` and `evidence/transport.json`. Exact timings are hardware-dependent.

CI additionally defines Semgrep and Gitleaks scans. **Those two tools and the GitHub workflow have not been run locally/on GitHub.** Their reports will be created by CI after repository setup. Do not present configured jobs as executed evidence.

## Findings, remediation and re-test

| Finding | Severity | Remediation | Re-test / disposition |
|---|---|---|---|
| Initial design did not bind exchange keys to the pinned signing identity | High | Device signs a domain-separated certificate over ID, epoch and exchange key; server and browser verify; local pins reject rollback | Crypto test mutates exchange key and epoch; both rejected. Browser rotation succeeds with valid certificate |
| Replaying an otherwise valid encrypted envelope | Medium | Persistent unique replay tombstone, signature/time checks, content-free audit event | First send 200, duplicate 409; replay signal visible; tombstone retained after expiry |
| Session theft after device/account revocation | High | Revalidate account, device and expiry on every authenticated request and WS delivery; proactively close invalid connections | Integration returns 401 / WS close 4001; live browser locks on admin revocation |
| Unauthenticated/other-group requests and ordinary-member admin action | High | Central session and membership checks plus explicit admin role | 401/403 tests and cross-user session-revoke 404 |
| Sensitive actions authorized by an old second-factor check | Medium | Five-minute step-up age gate, current single-use authenticator code to renew | Test forces stale step-up; device revoke returns 403 |
| Rotation interrupted between remote update and browser save could lose current key | Medium | Stage proposed key in encrypted vault; reconcile at next password+MFA sign-in | Normal rotation tested end-to-end; crash/fault-injection coverage remains a documented follow-up |
| False positive in focused DOM-sink regex | Low / tooling | Prevent whitespace backtracking from misclassifying static literal templates | Re-run static scan: no findings. User content is appended via textContent |
| Full per-message forward secrecy, initial active-relay trust and metadata visibility | Accepted limitations | Explicit protocol/threat model, manual epoch rotation, verification UX, minimized logging | Do not mark as fully remediated or claim audited ratchet security |

## Interpreting encrypted-storage evidence

Tests send recognizable plaintext and attachment filenames through real browser encryption. Database message rows and audit rows are searched for those sentinels and the same envelope is decrypted by the authorized recipient. This shows the implemented data path stores ciphertext; it does not prove a malicious replacement client could never upload plaintext. The relay can read account/channel metadata and decrypt MFA seeds with its master key, but it receives no device private message-decryption keys.

## Performance

Review generated JSON rather than copying stale benchmark numbers. The envelope-size figure includes JSON/base64 and per-device wrappers. The benchmark measures WebCrypto in Node on the same machine, not high-load concurrent browser traffic. Composer timing also displays real browser encryption and send duration. Loopback transport results are single samples, not p95 internet delivery measurements.
