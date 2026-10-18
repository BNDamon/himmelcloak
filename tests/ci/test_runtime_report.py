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
"""Offline fixture tests for CI runtime reporting."""
import importlib.util
import io
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("runtime_report", ROOT / "scripts/ci/runtime_report.py")
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)
FIXTURE = json.loads((Path(__file__).parent / "fixtures/runtime.json").read_text())


class RuntimeReportTests(unittest.TestCase):
    def fetch(self, pages):
        requests = []
        def opener(request, timeout):
            self.assertEqual(timeout, 30)
            requests.append(request.full_url)
            return io.BytesIO(json.dumps({"jobs": pages[len(requests) - 1]}).encode())
        jobs = reporter.fetch_jobs("https://api.github.com", "example/repo",
                                   FIXTURE["run"], "test-token", opener)
        return jobs, requests

    def test_pagination_and_exact_attempt(self):
        job = FIXTURE["jobs"][0]
        jobs, requests = self.fetch([[job] * 100, [job]])
        self.assertEqual(len(jobs), 101)
        self.assertEqual(len(requests), 2)
        self.assertIn("/attempts/2/jobs?per_page=100&page=2", requests[1])

    def test_empty_first_page(self):
        jobs, requests = self.fetch([[]])
        self.assertEqual(jobs, [])
        self.assertEqual(len(requests), 1)
        self.assertIn("elapsed unavailable", reporter.render_report(FIXTURE["run"], jobs))

    def test_empty_last_page(self):
        jobs, requests = self.fetch([[FIXTURE["jobs"][0]] * 100, []])
        self.assertEqual(len(jobs), 100)
        self.assertEqual(len(requests), 2)

    def test_null_timestamps_and_pipe_in_job_name(self):
        report = reporter.render_report(FIXTURE["run"], FIXTURE["jobs"])
        self.assertIn("| build/unit next | success | 30 |", report)
        self.assertIn("40 s", report)
        self.assertIn("Excluded 2 jobs", report)
        self.assertNotIn("missing start |", report)
        self.assertNotIn("missing end |", report)

    def test_null_run_start(self):
        run = dict(FIXTURE["run"], run_started_at=None)
        report = reporter.render_report(run, FIXTURE["jobs"])
        self.assertIn("elapsed unavailable", report)
        self.assertIn("| success | 30 |", report)

    def test_cancelled_run_has_no_baseline(self):
        run = dict(FIXTURE["run"], conclusion="cancelled")
        self.assertEqual(reporter.render_report(run, FIXTURE["jobs"]), "")

    def test_cancelled_and_skipped_jobs_are_not_measurements(self):
        jobs = [dict(FIXTURE["jobs"][0], conclusion=result) for result in ("cancelled", "skipped")]
        report = reporter.render_report(FIXTURE["run"], jobs)
        self.assertIn("Excluded 2 jobs", report)
        self.assertIn("elapsed unavailable", report)

    def test_failed_run_keeps_conclusion(self):
        run = dict(FIXTURE["run"], conclusion="failure")
        self.assertIn("result: failure", reporter.render_report(run, FIXTURE["jobs"]))


if __name__ == "__main__":
    unittest.main()
