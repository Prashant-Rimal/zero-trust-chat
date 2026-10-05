#!/usr/bin/env bash
# Server-side deploy script. Install once as /usr/local/bin/cipherroom-deploy (root-owned);
# GitHub Actions can run only this, through a forced SSH command. See docs/DEPLOYMENT.md.
#
# Usage: cipherroom-deploy <40-character commit sha>
set -euo pipefail

APP_DIR=/opt/cipherroom/app
APP_USER=cipherroom
SERVICE=cipherroom
BRANCH=main

sha="${1:-}"
# The argument arrives from the network, so accept nothing but a full commit hash.
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: cipherroom-deploy <commit sha>" >&2
  exit 2
fi

as_app() { sudo -u "$APP_USER" -H "$@"; }
cd "$APP_DIR"

previous="$(as_app git rev-parse HEAD)"
as_app git fetch --quiet origin "$BRANCH"
# Only commits that are actually on the deploy branch can be deployed.
if ! as_app git merge-base --is-ancestor "$sha" "origin/$BRANCH"; then
  echo "refusing: $sha is not on origin/$BRANCH" >&2
  exit 3
fi
if [[ "$previous" == "$sha" ]]; then
  echo "already at $sha"
  exit 0
fi

build() {
  as_app git checkout --quiet --detach "$1"
  as_app npm ci --no-audit --no-fund
  as_app npm run build
}
healthy() {
  local port
  port="$(grep -E '^PORT=' "$APP_DIR/.env" | cut -d= -f2 || true)"
  for _ in $(seq 1 20); do
    # 401 from /api/me proves the process is up and the database connection works.
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port:-3000}/api/me")" == "401" ]]; then return 0; fi
    sleep 1
  done
  return 1
}

echo "deploying $previous -> $sha"
build "$sha"
systemctl restart "$SERVICE"
if healthy; then
  echo "deployed $sha"
  exit 0
fi

echo "health check failed; rolling back to $previous" >&2
journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
build "$previous"
systemctl restart "$SERVICE"
healthy && echo "rolled back to $previous" >&2
exit 1
