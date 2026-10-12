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

# Pinned stable releases. Renovate bumps each tag and its commit together (renovate.json).
PINNED_WOLFSSL_REF=v5.9.4-stable PINNED_WOLFSSL_COMMIT=3c5eead44904df64e6a5a1f4ebdce377d35a849a
PINNED_CURL_REF=curl-8_22_0 PINNED_CURL_COMMIT=01346829096c61b372692f6dc43ffa778c6caccd
WOLFSSL_REF=${WOLFSSL_REF:-$PINNED_WOLFSSL_REF}
CURL_REF=${CURL_REF:-$PINNED_CURL_REF}
WOLFSSL_COMMIT=${WOLFSSL_COMMIT:-}
CURL_COMMIT=${CURL_COMMIT:-}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
NATIVE_PREFIX=${NATIVE_PREFIX:-"$REPO_ROOT/.native"}
if [[ "$NATIVE_PREFIX" != /* ]]; then
    NATIVE_PREFIX="$(pwd)/$NATIVE_PREFIX"
fi

resolve_commit() {
    local remote=$1 ref=$2 matches commit
    if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        printf '%s\n' "$ref"
        return
    fi
    matches=$(git ls-remote --exit-code "$remote" \
        "refs/tags/$ref^{}" "refs/tags/$ref" "refs/heads/$ref")
    commit=$(awk -v ref="$ref" '$2 == "refs/tags/" ref "^{}" { print $1; exit }' <<< "$matches")
    if [[ -z "$commit" ]]; then
        commit=$(awk -v ref="$ref" '$2 == "refs/heads/" ref { print $1; exit }' <<< "$matches")
    fi
    if [[ -z "$commit" ]]; then
        commit=$(awk -v ref="$ref" '$2 == "refs/tags/" ref { print $1; exit }' <<< "$matches")
    fi
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "Could not resolve $ref from $remote" >&2; return 1; }
    printf '%s\n' "$commit"
}

if [[ -z "$WOLFSSL_COMMIT" ]]; then
    if [[ "$WOLFSSL_REF" == "$PINNED_WOLFSSL_REF" ]]; then
        WOLFSSL_COMMIT=$PINNED_WOLFSSL_COMMIT
    else
        WOLFSSL_COMMIT=$(resolve_commit https://github.com/wolfSSL/wolfssl.git "$WOLFSSL_REF")
    fi
fi
if [[ -z "$CURL_COMMIT" ]]; then
    if [[ "$CURL_REF" == "$PINNED_CURL_REF" ]]; then
        CURL_COMMIT=$PINNED_CURL_COMMIT
    else
        CURL_COMMIT=$(resolve_commit https://github.com/curl/curl.git "$CURL_REF")
    fi
fi
[[ "$WOLFSSL_COMMIT" =~ ^[0-9a-f]{40}$ && "$CURL_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Native dependency commits must be full lowercase Git SHA-1 values" >&2
    exit 1
}
REFS="wolfssl $WOLFSSL_REF $WOLFSSL_COMMIT
curl $CURL_REF $CURL_COMMIT"

if [[ -f "$NATIVE_PREFIX/lib/pkgconfig/libcurl.pc" && -f "$NATIVE_PREFIX/lib/pkgconfig/wolfssl.pc" ]]; then
    if [[ -f "$NATIVE_PREFIX/lib/libcurl.a" && -f "$NATIVE_PREFIX/lib/libwolfssl.a" &&
          -f "$NATIVE_PREFIX/.himmelcloak-refs" ]] &&
       [[ "$(cat "$NATIVE_PREFIX/.himmelcloak-refs")" == "$REFS" ]]; then
        echo "Using native dependencies in $NATIVE_PREFIX"
        exit 0
    fi
    printf -v escaped_prefix '%q' "$NATIVE_PREFIX"
    echo "Native prefix is incomplete or uses different refs." >&2
    echo "Remove it with: rm -rf -- $escaped_prefix" >&2
    echo "Or choose a new NATIVE_PREFIX." >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

fetch_commit() {
    local remote=$1 commit=$2 destination=$3 actual
    git init --quiet "$destination"
    git -C "$destination" remote add origin "$remote"
    git -C "$destination" fetch --quiet --depth 1 origin "$commit"
    git -C "$destination" checkout --quiet --detach FETCH_HEAD
    actual=$(git -C "$destination" rev-parse HEAD)
    [[ "$actual" == "$commit" ]] || { echo "Fetched unexpected commit from $remote" >&2; return 1; }
}

fetch_commit https://github.com/wolfSSL/wolfssl.git "$WOLFSSL_COMMIT" "$BUILD_DIR/wolfssl"
pushd "$BUILD_DIR/wolfssl" >/dev/null
./autogen.sh
./configure --prefix="$NATIVE_PREFIX" --enable-all --enable-static --disable-shared
make -j"$(nproc)"
make install
popd >/dev/null

fetch_commit https://github.com/curl/curl.git "$CURL_COMMIT" "$BUILD_DIR/curl"
pushd "$BUILD_DIR/curl" >/dev/null
autoreconf -fi
PKG_CONFIG_PATH="$NATIVE_PREFIX/lib/pkgconfig" ./configure \
    --prefix="$NATIVE_PREFIX" \
    --with-wolfssl="$NATIVE_PREFIX" \
    --without-libpsl \
    --enable-static \
    --disable-shared
make -j"$(nproc)"
make install
popd >/dev/null

"$NATIVE_PREFIX/bin/curl-config" --ssl-backends | grep -qx 'wolfSSL'
printf '%s\n' "$REFS" > "$NATIVE_PREFIX/.himmelcloak-refs"
