# Generated evidence

- `tests.tap`: actual Node adversarial test-run output (`npm test`).
- `browser.json`: actual two-browser end-to-end assertions (`npm run test:browser`).
- `screenshots/`: synthetic lab account desktop/mobile previews, not real user data.
- `benchmark.json`: measured crypto overhead (`npm run benchmark`).
- `transport.json`: measured loopback HTTP-to-WebSocket flow with decryption/assertion overhead (`npm test`).
- `static-scan.json`: focused source/security policy checks (`npm run security`).
- `dependency-audit.json`: npm audit output; regenerate with `npm audit --json > evidence/dependency-audit.json`.

No Semgrep/Gitleaks or remote deployment success is claimed here until the configured GitHub workflow actually executes. Generated timings vary by machine and run. Do not commit real data directories, authenticator secrets, private keys, cookies or production conversation screenshots.
