#!/usr/bin/env python3
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
"""Check that renovate.json's regex managers still find every pin they are meant to bump."""
import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1])
RUST_PINS = {"rust-toolchain.toml": 1, "Cargo.toml": 1, "tests/build/Dockerfile": 2}


def matches(manager):
    files = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    for pattern in manager["managerFilePatterns"]:
        regex = re.compile(pattern.strip("/"))
        for path in files:
            rel = path.relative_to(ROOT).as_posix()
            if not regex.search(rel):
                continue
            text = path.read_text(errors="ignore")
            for match_string in manager["matchStrings"]:
                for hit in re.finditer(match_string.replace("(?<", "(?P<"), text):
                    yield rel, hit.groupdict()


def main():
    config = json.loads((ROOT / "renovate.json").read_text())
    found = {m["depNameTemplate"]: list(matches(m)) for m in config["customManagers"]}
    errors = []
    for dep in ("wolfssl", "curl"):
        hits = found.get(dep, [])
        if len(hits) != 1 or not re.fullmatch(r"[0-9a-f]{40}", hits[0][1].get("currentDigest") or ""):
            errors.append(f"{dep}: expected one tag and commit pin, found {hits}")
    if len(found.get("renovate", [])) != 1:
        errors.append(f"renovate: expected one validator pin, found {found.get('renovate', [])}")
    rust = found.get("rust", [])
    versions = {hit["currentValue"] for _, hit in rust}
    counts = collections.Counter(rel for rel, _ in rust)
    wrong = {f: counts[f] for f, want in RUST_PINS.items() if counts[f] != want}
    if wrong or len(versions) != 1:
        errors.append(f"rust: wrong pin counts {wrong} or mismatched versions {sorted(versions)}")
    for dep, hits in found.items():
        print(dep, ", ".join(f"{rel}={hit['currentValue']}" for rel, hit in hits))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
