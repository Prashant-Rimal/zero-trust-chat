# Coursework mapping and remaining milestones

| Requirement | Implementation / evidence | Status |
|---|---|---|
| Real-world problem and architecture | ARCHITECTURE.md, Mermaid trust boundaries, measurable criteria | Implemented/documented |
| Threat model | THREAT-MODEL.md prioritized risks and accepted limits | Documented |
| Secure authentication, 2FA, two roles | scrypt, TOTP, admin/member, CSRF/session controls | Implemented/tested |
| End-to-end authenticated encryption / exchange | AES-GCM + signed ECDH/HKDF per-device envelopes | Implemented/tested; custom unaudited protocol |
| Key rotation / forward-secrecy design | Signed epochs, manual old-key discard, fingerprint verification | Rotation implemented; full ratchet forward secrecy not implemented |
| Realtime 1:1 and group chat | WebSocket notifications, strict membership and device authorization | Implemented/browser-tested |
| Encrypted attachments/storage | Client encrypted bytes/name, SQLite ciphertext, no content logs | Implemented/tested |
| Ephemeral / integrity / replay | Signed expiry, periodic cleanup, AEAD + ECDSA, tombstones | Implemented/tested |
| Device and session management | Device enrollment/revocation/rotation, individual session termination | Implemented/tested |
| Security dashboard | Login failures, MFA failures, enrollment, key changes, replay/tamper, revocation signals | Implemented; rule-based signals, no ML anomaly model |
| Metadata minimization | Privacy UI, minimized audit schema/retention, documented observability | Implemented/documented; metadata not anonymous |
| Advanced security mechanism | Continuous Zero Trust session/device checks, least privilege, step-up | Implemented/evaluated |
| Three or more assurance techniques | Dynamic security tests, browser tests, focused static checks, npm audit | Executed with repository evidence |
| Automated CI/CD stages | GitHub Actions build → SAST → test → dependencies/secrets → staging/artifact | Configured; remote execution pending GitHub setup |
| Findings/remediation/retest | ASSURANCE.md plus TAP/JSON artifacts | Included |
| Monitoring and incident response | Incident runbook and live revocation tests | Implemented/demonstrated |
| Encryption and latency overhead | Generated benchmark and loopback delivery JSON, browser composer timing | Measured |
| Reproducibility | README, lockfile, setup/env instructions, test scripts | Included |
| GitHub collaboration / peer review | No repository or remote created yet, as requested | Pending team work |
| Two meaningful commits/member/week from Week 6 | Must be authentic ongoing contributions with dates and authors | Cannot be backfilled or claimed by this build |
| Authorized testing and ethics | Loopback-only synthetic harness, no external attack targets | Implemented/documented |

## Before submission

- Create the collaborative repository when authorized; preserve meaningful commit/PR history, reviews, task ownership and weekly contributions.
- Run the configured workflow remotely, review Semgrep/Gitleaks findings and retain actual reports and workflow links.
- Record the real team incident demonstration and explain the limits of initial key trust and forward secrecy accurately.
- Choose a deployment target if a hosted demo is required; configure HTTPS and secure cookies, restrict registration and protect secrets/metadata at rest.
- Add sustained concurrent-load testing, accessibility audit, fault injection for interrupted rotation, and an independently reviewed messaging protocol before making production claims.
