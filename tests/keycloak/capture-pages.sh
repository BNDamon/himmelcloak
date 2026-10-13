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
#
# Capture Keycloak login pages as page-classifier fixtures, in the base and
# keycloak.v2 login themes. Run `make oracle-up` first. The script adds the
# charter's bob and carol OTP users to the running test realm only;
# realm-export.json is not changed. Session-specific values are replaced with
# placeholders.
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
out_dir="$script_dir/../fixtures/keycloak"
ca="$script_dir/.generated/ca.pem"
kc=https://keycloak.test:8443
realm=himmelcloak-test
client=himmelcloak-test-client
redirect=http://127.0.0.1:8845/himmelcloak/callback
password=correct-horse-battery-staple
kc_curl=(curl --silent --show-error --fail --cacert "$ca" --resolve keycloak.test:8443:127.0.0.1)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

admin_token() {
    "${kc_curl[@]}" "$kc/realms/master/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=admin-cli \
        -d username=admin -d password=local-test-only |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

admin() {
    local method=$1 path=$2
    "${kc_curl[@]}" -X "$method" -H "Authorization: Bearer $(admin_token)" \
        -H 'Content-Type: application/json' --data-binary @- "$kc/admin/realms/$realm$path"
}

# One OTP credential as "label:subType:digits:algorithm".
otp_credential() {
    # Keycloak only renders the page; these secrets never produce a usable code.
    python3 -c 'import json, sys
label, sub_type, digits, algorithm = sys.argv[1].split(":")
print(json.dumps({"type": "otp", "userLabel": label,
    "secretData": json.dumps({"value": "fixture-secret-" + label.replace(" ", "-")}),
    "credentialData": json.dumps({"subType": sub_type, "digits": int(digits), "counter": 0,
                                  "period": 30, "algorithm": algorithm})}))' "$1"
}

otp_user() {
    local name=$1 credentials
    shift
    credentials="{\"type\":\"password\",\"value\":\"$password\",\"temporary\":false}"
    for spec in "$@"; do
        credentials+=",$(otp_credential "$spec")"
    done
    printf '{"username":"%s","enabled":true,"emailVerified":true,"firstName":"%s",' "$name" "$name"
    printf '"lastName":"Fixture","email":"%s@example.invalid","credentials":[%s]}' "$name" "$credentials"
}

form_action() {
    python3 -c 'import html, re, sys
match = re.search(r"<form[^>]*\baction=\"([^\"]+)\"", sys.stdin.read())
sys.exit("no form action") if not match else print(html.unescape(match.group(1)))'
}

# Replace values that differ on every capture with fixed placeholders.
scrub() {
    python3 -c '
import re, sys
page = sys.stdin.read()
page = re.sub(r"\b(session_code|execution|tab_id|client_data|kc_locale)=[^&\"\s]+", r"\1=FIXTURE", page)
page = re.sub(r"(checkAuthSession\(\s*\")[^\"]+", r"\1FIXTURE", page)
# Keycloak picks a new static-resource path on every server start.
page = re.sub(r"/resources/[a-z0-9]+/", "/resources/FIXTURE/", page)
ids = {}
def stable(match):
    # Same random ID in, same placeholder out, so links between fields survive.
    return "00000000-0000-4000-8000-%012d" % ids.setdefault(match.group(0), len(ids) + 1)
sys.stdout.write(re.sub(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", stable, page))'
}

capture() {
    local theme=$1 user=$2 jar="$work/cookies" page action query
    rm -f "$jar"
    query="client_id=$client&response_type=code&scope=openid&state=fixture-state&nonce=fixture-nonce"
    query+="&redirect_uri=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$redirect")"
    page=$("${kc_curl[@]}" -c "$jar" -b "$jar" "$kc/realms/$realm/protocol/openid-connect/auth?$query")
    printf '%s' "$page" | scrub > "$out_dir/$theme/login.html"
    action=$(printf '%s' "$page" | form_action)
    "${kc_curl[@]}" -c "$jar" -b "$jar" "$action" \
        --data-urlencode "username=$user" --data-urlencode "password=$password" |
        scrub > "$out_dir/$theme/$3"
}

mkdir -p "$out_dir/base" "$out_dir/keycloak.v2"
# The one-time-code users from the charter's test realm (Table 23): bob has one TOTP device;
# carol has TOTP (SHA-256, 8 digits) and HOTP (the charter leaves HOTP settings open, so it
# uses Keycloak's defaults).
{
    printf '{"ifResourceExists":"OVERWRITE","users":['
    otp_user bob "Authenticator app:totp:6:HmacSHA1"
    printf ','
    otp_user carol "Authenticator app:totp:8:HmacSHA256" "Hardware token:hotp:6:HmacSHA1"
    printf ']}'
} | admin POST /partialImport > /dev/null

for theme in keycloak.v2 base; do
    printf '{"loginTheme":"%s"}' "$theme" | admin PUT "" > /dev/null
    capture "$theme" bob login-otp.html
    capture "$theme" carol login-otp-devices.html
    echo "captured $theme"
done

# Record which Keycloak release rendered these pages, so a field change can be traced to it.
"${kc_curl[@]}" -H "Authorization: Bearer $(admin_token)" "$kc/admin/serverinfo" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["systemInfo"]["version"])' \
    > "$out_dir/KEYCLOAK_VERSION"
echo "keycloak $(cat "$out_dir/KEYCLOAK_VERSION")"
