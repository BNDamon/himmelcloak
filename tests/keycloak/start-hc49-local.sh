#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Use a dedicated disposable Keycloak distribution, not a production installation.
set -euo pipefail
: "${HC49_KEYCLOAK_HOME:?Set HC49_KEYCLOAK_HOME to a dedicated disposable Keycloak installation}"
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FIXTURE_DIR=${HC49_FIXTURE_DIR:-/tmp/himmelcloak-hc49-live}
mkdir -p "$FIXTURE_DIR" "$HC49_KEYCLOAK_HOME/data/import"
if [[ ! -f "$FIXTURE_DIR/server.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
    -keyout "$FIXTURE_DIR/server.key" -out "$FIXTURE_DIR/server.crt" \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  chmod 600 "$FIXTURE_DIR/server.key"
fi
cp "$REPO_ROOT/tests/keycloak/hc49-test-realm.json" "$HC49_KEYCLOAK_HOME/data/import/hc49-test-realm.json"
exec "$HC49_KEYCLOAK_HOME/bin/kc.sh" start-dev --import-realm \
  --http-enabled=false --https-port=18443 --http-host=127.0.0.1 \
  --hostname=https://localhost:18443 --https-certificate-file="$FIXTURE_DIR/server.crt" \
  --https-certificate-key-file="$FIXTURE_DIR/server.key" --http-management-port=19000
