# Deployment

The app is **one long-running Node process** that serves HTTP and WebSocket on the same port, plus a Postgres database. It is not a fit for request-scoped serverless functions, because WebSocket connections and the realtime hub need a process that stays up.

No container is required. Any host that can run `node serve.mjs` behind TLS works (a VM, Railway, Render, Fly Machines, a university server).

## 1. Database (Neon)

1. Create a Neon project and copy the **pooled** connection string.
2. Nothing else: the schema is created on first boot (`migrate()` in `src/server/db.ts`; every statement is `IF NOT EXISTS`).

For CI, create a separate Neon branch and use it as `TEST_DATABASE_URL`. The test suite drops and recreates the `public` schema, so never point it at real data.

## 2. Environment

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | Neon pooled connection string |
| `SERVER_SECRET` | yes | 32 random bytes, base64. Seals TOTP seeds, keys pseudonyms. **Back it up**: losing it locks everyone out of 2FA |
| `APP_ORIGIN` | yes | Public origin, e.g. `https://chat.example.com`. Must match exactly what browsers send |
| `PORT`, `HOST` | no | Default `3000`, `0.0.0.0` |
| `TRUST_PROXY` | behind a proxy | `1` if exactly one trusted reverse proxy appends `X-Forwarded-For` |
| `DP_EPSILON`, `DP_WINDOW_MINUTES` | no | Analytics privacy parameters (default `1`, `1440`) |

Generate the secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## 3. Build and run

```bash
npm ci
```

```bash
npm run build
```

```bash
npm start
```

The process refuses to start if `SERVER_SECRET` is missing or the database is unreachable.

## 4. TLS and proxy

Terminate TLS in front of the app and forward both HTTP and WebSocket upgrades to it. With `APP_ORIGIN` starting `https://` the app sets `Secure` cookies and HSTS.

Set `TRUST_PROXY=1` only if the proxy is the sole way to reach the app. Otherwise clients could spoof their network identity and weaken per-IP rate limits and session-context checks.

## 5. After deploying

```bash
TARGET_URL=https://chat.example.com npm run smoke
```

Registers two throwaway accounts and exchanges encrypted messages and a file over the real network path. Then create your own account first: **the first account to complete two-factor setup becomes the administrator.**

## CI (GitHub Actions)

`.github/workflows/ci.yml`:

| Job | Does |
|---|---|
| `verify` | `npm ci`, typecheck, the full security test suite, production build |
| `smoke` | Starts the built server on the runner and runs the two-client smoke test over real HTTP/WebSocket; fails if the server log contains ids in route fields |
| `benchmark` | Runs the overhead benchmark and uploads `benchmark.json` |
| `postgres` | Re-runs the security suite against Neon. Opt in with repository variable `RUN_NEON_TESTS=true` and secret `TEST_DATABASE_URL` |
| `audit` | `npm audit` at moderate severity |

## Continuous deployment (GitHub Actions → your server)

`.github/workflows/deploy.yml` runs after `CI` succeeds on `main` (or by hand from the Actions tab). It opens one SSH connection and passes one value: the commit hash that CI tested. Everything else happens in `deploy/cipherroom-deploy.sh` on the server, which fetches, refuses any commit not on `origin/main`, builds, restarts the service, checks health, and rolls back to the previous commit if the health check fails.

The design keeps the GitHub side weak on purpose:

- The Actions key logs in as a `deploy` user whose key is locked (`authorized_keys` forced command) to the deploy script. It cannot open a shell, forward ports or run anything else.
- `deploy` may run exactly one command as root through `sudo`.
- The script is a root-owned copy in `/usr/local/bin`, not the file in the repository, so a pushed commit cannot change what runs as root. Re-copy it deliberately when it changes.
- The server's SSH host key is pinned in a secret rather than trusted on first connect.
- No application secret (`DATABASE_URL`, `SERVER_SECRET`) is stored in GitHub; they stay in `.env` on the server.

A push to `main` can still run code on the server as the unprivileged `cipherroom` user, because building runs the repository's own build. Protect `main` accordingly.

### One-time server setup

Assumes the server is already set up as in sections 1–4 with the app in `/opt/cipherroom/app`, running as user `cipherroom` under the `cipherroom` systemd service.

```bash
install -o root -g root -m 755 /opt/cipherroom/app/deploy/cipherroom-deploy.sh /usr/local/bin/cipherroom-deploy
useradd --create-home --shell /bin/bash deploy
echo 'deploy ALL=(root) NOPASSWD: /usr/local/bin/cipherroom-deploy' > /etc/sudoers.d/cipherroom-deploy
chmod 440 /etc/sudoers.d/cipherroom-deploy && visudo -cf /etc/sudoers.d/cipherroom-deploy
install -d -o deploy -g deploy -m 700 /home/deploy/.ssh
ssh-keygen -t ed25519 -N '' -C github-actions-deploy -f /root/gha_deploy_key
echo "restrict,command=\"sudo /usr/local/bin/cipherroom-deploy \\\"\$SSH_ORIGINAL_COMMAND\\\"\" $(cat /root/gha_deploy_key.pub)" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys && chmod 600 /home/deploy/.ssh/authorized_keys
```

### GitHub settings (Settings → Secrets and variables → Actions)

| Kind | Name | Value |
|---|---|---|
| Secret | `DEPLOY_HOST` | Server IP or hostname |
| Secret | `DEPLOY_SSH_KEY` | Contents of `/root/gha_deploy_key` (then delete that file from the server) |
| Secret | `DEPLOY_HOST_KEY` | One `known_hosts` line: `<DEPLOY_HOST value> ` followed by the contents of `/etc/ssh/ssh_host_ed25519_key.pub` |
| Variable | `APP_URL` | Public URL, e.g. `https://chat.example.com` (no trailing slash) |
| Variable | `DEPLOY_ENABLED` | `true` |

The deploy job does not run the smoke test against production, because that registers accounts. It checks that the site returns 200, the API answers, and the Content-Security-Policy header is present.

## Operations

- **Single instance.** Rate limits and the realtime hub are in memory.
- **Idle cost.** Background sweeps only run while requests arrive or sockets are connected, so a Neon database can suspend when nobody is online.
- **Data retention.** Queued ciphertext: until delivered or expired. Audit: 30 days. Expired sessions: 24 hours. Unfinished sign-ups: 1 hour.
- **Rotating `SERVER_SECRET`** is not supported without re-enrolling TOTP for every account.
- **Backups** contain ciphertext, public keys, hashed login keys and sealed TOTP seeds. They do not contain message content or private keys.
