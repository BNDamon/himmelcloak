#!/usr/bin/env bash
# Himmelcloak native Keycloak authentication
# Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
# Aidan Garske, Harrison Barrett, and Harman Samra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

if [[ "${1:-}" == "--verbose" ]]; then
    verbose=1
    shift
else
    verbose=0
fi
if [[ $# -ne 0 ]]; then
    echo 'Usage: tests/keycloak/run.sh [--verbose]' >&2
    exit 2
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
compose=(docker compose -f "$script_dir/docker-compose.yml")

"$script_dir/bootstrap-cert.sh"
"${compose[@]}" up -d --pull always --force-recreate keycloak
"${compose[@]}" build tester

if [[ "$verbose" == 0 ]]; then
    "${compose[@]}" run --rm tester
    exit 0
fi

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
result=0
"${compose[@]}" run --rm -e HIMMELCLOAK_TEST_VERBOSE=1 tester \
    cargo test --locked --features webauthn-virtual --lib --test live_keycloak -- --ignored --nocapture || result=$?

echo 'Keycloak server authentication events:'
"${compose[@]}" logs --no-color --since "$started" keycloak \
    | awk -f "$script_dir/auth-events.awk"
exit "$result"
