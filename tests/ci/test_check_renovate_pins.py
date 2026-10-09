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
"""Failure cases for scripts/check-renovate-pins.py, run against a copy of the repo's pin files."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check-renovate-pins.py"
FILES = [
    "renovate.json", "scripts/build-native.sh", "rust-toolchain.toml", "Cargo.toml", "tests/build/Dockerfile",
    ".github/workflows/renovate-config.yml",
]


class CheckRenovatePinsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        for rel in FILES:
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO / rel, self.root / rel)

    def tearDown(self):
        self.dir.cleanup()

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def check(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root)], capture_output=True, text=True)

    def assert_fails(self, reason):
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(reason, result.stderr)

    def test_current_pins_pass(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reformatted_wolfssl_pin_fails(self):
        self.edit("scripts/build-native.sh", " PINNED_WOLFSSL_COMMIT=", "  PINNED_WOLFSSL_COMMIT=")
        self.assert_fails("wolfssl: expected one tag and commit pin")

    def test_duplicate_curl_pin_fails(self):
        line = next(l for l in (self.root / "scripts/build-native.sh").read_text().splitlines()
                    if l.startswith("PINNED_CURL_REF="))
        self.edit("scripts/build-native.sh", line, line + "\n" + line)
        self.assert_fails("curl: expected one tag and commit pin")

    def test_mismatched_rust_version_fails(self):
        self.edit("rust-toolchain.toml", 'channel = "1.', 'channel = "2.')
        self.assert_fails("mismatched versions")

    def test_dropped_dockerfile_rust_pin_fails(self):
        self.edit("tests/build/Dockerfile", "--toolchain 1.", "--toolchain stable-1.")
        self.assert_fails("wrong pin counts")

    def test_unpinned_validator_fails(self):
        self.edit(".github/workflows/renovate-config.yml", "renovate@", "renovate@latest-")
        self.assert_fails("renovate: expected one validator pin")

    def test_missing_rust_pin_file_fails(self):
        (self.root / "Cargo.toml").unlink()
        self.assert_fails("wrong pin counts")


if __name__ == "__main__":
    unittest.main()
