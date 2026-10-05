# Running and deploying

## Local operation

`npm start` serves on 127.0.0.1:3000. Stop with Ctrl+C. To change the port, set both PORT and APP_ORIGIN:

```powershell
$env:PORT = '3010'
$env:APP_ORIGIN = 'http://127.0.0.1:3010'
npm start
```

Environment variables are read from the process environment, not automatically from `.env`. `.env.example` documents available names. `DATA_DIR` chooses a persistent directory. Do not commit that directory, master key, database or backups.

## HTTPS deployment requirements

The app intentionally defaults to loopback. Before exposing it elsewhere:

1. Enroll the intended first administrator in a controlled environment; introduce invite-only provisioning before public registration.
2. Use an HTTPS reverse proxy with WebSocket forwarding and a real certificate. Set APP_ORIGIN to the **exact external HTTPS origin**, and COOKIE_SECURE=1. Leave the Node listener on a private/loopback interface.
3. Forward `/ws` upgrades. Do not log request bodies, cookies, CSRF tokens, MFA seeds or credentials. Disable proxy query/body capture. Review access-log retention: this app's metadata minimization cannot control upstream logs.
4. Run under a dedicated unprivileged OS user. Restrict `data/` access to that account; use Windows ACLs or Unix permissions and encrypted volumes. A 0600 creation mode is not an NTFS ACL policy.
5. Secure and encrypt backups; store the server master key separately in a managed secret system for production. Current local `master.key` is co-located for reproducibility, not production key custody. Never delete it while expecting MFA data to remain usable.
6. Add persistent/distributed rate limiting and limits for users/devices/channels; enforce reverse-proxy body and connection limits. Current in-memory rate limiting and synchronous SQLite suit a local lab.
7. Use a vetted messaging protocol, external security assessment, signed/reproducible client distribution and key transparency before relying on it for sensitive real-world communications.

No host-based encryption protects metadata while the application process is compromised. No app-level E2EE protects clients when malicious code runs in their browser.

## CI / delivery

Workflow stages: **Build → SAST → Test → Dependency/Secrets → isolated staging deploy + smoke test + artifact**. Each stage gates the next. Jobs have read-only repository permissions. Reports are uploaded even when tests fail. Semgrep project rules and Gitleaks history checks supplement the local focused scanner.

The deploy stage runs the assembled app inside a disposable runner and checks its homepage. It does **not** deploy to a public cloud, create infrastructure or publish secrets. A later production deploy needs an explicitly chosen host, protected environment, TLS, secret management, backups and rollback policy. Pin CI tools/actions to reviewed immutable versions/digests before production; Semgrep currently installs from the package index.

## Recovery limitations

Revoked accounts/devices are deliberately not reactivated in the UI. A revoked device needs a new device identity after legitimate account verification; use a fresh browser profile. In a lab, a completely new account/channel demonstrates recovery after containment. Do not edit SQLite records to silently bypass MFA. No password or authenticator reset implementation exists yet.

Start a fresh disposable lab by setting DATA_DIR to a **new empty path**, rather than deleting existing evidence or user data. Existing browser identities can be isolated with a fresh browser profile. Retained ciphertext does not become readable by a replacement device.
