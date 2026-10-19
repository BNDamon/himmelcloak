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
"""Report durations for a completed GitHub Actions workflow attempt."""
import datetime
import json
import os
import urllib.request


def timestamp(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def cell(value):
    return str(value).replace("|", "/").replace("\r", " ").replace("\n", " ")


def fetch_jobs(api_url, repository, run, token, opener=None):
    """Fetch every page of the exact attempt, including an empty final page."""
    opener = opener or urllib.request.urlopen
    jobs = []
    page = 1
    while True:
        url = (f"{api_url}/repos/{repository}/actions/runs/{run['id']}"
               f"/attempts/{run['run_attempt']}/jobs?per_page=100&page={page}")
        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        })
        with opener(request, timeout=30) as response:
            batch = json.load(response)["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            return jobs
        page += 1


def render_report(run, jobs):
    """Missing timestamps never become invented zero-duration measurements."""
    if run["conclusion"] == "cancelled":
        return ""
    completed = [job for job in jobs
                 if job.get("started_at") and job.get("completed_at")
                 and job.get("conclusion") not in ("cancelled", "skipped")]
    lines = [f"## Runtime: {cell(run['name'])}",
             f"Run: {run['html_url']} (attempt {run['run_attempt']})",
             f"Commit: `{run['head_sha']}`; result: {run['conclusion']}",
             "", "| Job | Result | Seconds |", "| --- | --- | ---: |"]
    for job in completed:
        seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
        lines.append(f"| {cell(job['name'])} | {cell(job['conclusion'])} | {seconds:.0f} |")
    if completed and run.get("run_started_at"):
        seconds = (max(timestamp(job["completed_at"]) for job in completed)
                   - timestamp(run["run_started_at"])).total_seconds()
        lines.append(f"\nWorkflow elapsed from run start through last measured job: {seconds:.0f} s")
    else:
        lines.append("\nWorkflow elapsed unavailable: no measured jobs or missing run start.")
    omitted = len(jobs) - len(completed)
    if omitted:
        lines.append(f"Excluded {omitted} jobs with missing timestamps or cancelled/skipped results.")
    return "\n".join(lines) + "\n"


def main():
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as stream:
        run = json.load(stream)["workflow_run"]
    if run["conclusion"] == "cancelled":
        print("Cancelled run: no baseline recorded.")
        return
    jobs = fetch_jobs(os.environ["GITHUB_API_URL"], os.environ["GITHUB_REPOSITORY"],
                      run, os.environ["GH_TOKEN"])
    report = render_report(run, jobs)
    print(report, end="")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write(report)


if __name__ == "__main__":
    main()
