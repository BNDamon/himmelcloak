# CI gates and runtime baseline

## Merge requirements

Configure the main and release branch rules to require these exact check names:

- `Supply-chain licenses and advisories`
- `Rust format, Clippy, unit tests`
- `Keycloak stable login`

These checks have no path filters. Core CI, including cargo-deny, runs on every
push to main/release branches and every pull request. Keycloak uses the same
triggers, with manual dispatch also available. Use unique check names in other workflows. If a merge
queue is enabled, add its `merge_group` event before requiring these checks there.
Repository administrators must apply the branch rules in GitHub; a workflow alone
does not prevent merging. This change documents the required settings and does
not claim that the remote branch rules have been configured.

Keep `Keycloak nightly login` and `Record CI runtime` out of required checks.
The matrix has fail-fast disabled and neither channel suppresses failures.
Nightly failures produce a red optional check and a failed workflow, plus a
warning and summary. Stable continues independently and can pass. Branch rules
must require the named stable check, not every check or the entire workflow.
This preserves GitHub's normal failed-run visibility and notifications for users
subscribed to Actions failures; it does not automatically subscribe teammates.
The PR author checks this optional result and brings regressions to the reviewer.
There is no added daily schedule. Image pulls happen inside each login job so a
broken nightly image cannot prevent stable startup. Stable tag discovery is a
shared prerequisite; its failure is blocking.

Cross-distro and native compatibility workflows remain additional regression
signals. Their matrix names are moving values; they are not added as required
checks by this slice. Existing branch rules should be reviewed before replacing
them with the minimum set above.

## Supply-chain policy

`deny.toml` is the license allow-list. The pinned cargo-deny action checks all
workspace features with the committed lockfile and includes dev-dependencies.
Vulnerability advisories are errors by cargo-deny default; yanked crates are
explicitly denied. No advisory exceptions are configured.

The license exception for `wolfssl-wolfcrypt =2.2.0` is deliberately exact. Its
published manifest uses deprecated `GPL-3.0`; the source header grants version 3
or later. A dependency bump using that identifier is expected to fail until the
new published metadata and source headers are reviewed. Update the exception
only after that review, or remove it if upstream adopts an already allowed SPDX
identifier. Do not broaden it to all versions.

The cargo-deny Rust version pin is managed alongside `rust-toolchain.toml` by
Renovate and verified by `scripts/check-renovate-pins.py`. A fresh RustSec
lookup failure also fails the gate. Informational unmaintained/unsound notices
retain cargo-deny's defaults. Reproduce with:

```sh
cargo deny --locked --all-features check licenses advisories
```

Do not widen the license policy or suppress an advisory merely to make CI green.
Review an upstream fix or a documented policy change instead.

## Recorded baseline

Pre-change snapshot: main commit `9a33cfaf6e1084efe2866af804086c9081065f97`,
2026-10-17, all four workflows successful, attempt 1. Durations below use the
GitHub Actions jobs API: earliest job start through latest job completion,
including gaps between dependent jobs. Jobs run concurrently, so do not sum
these values. This is one observation, not a performance target or median.
Cache warmth was not measured.

| Workflow | Jobs | Elapsed | Evidence |
| --- | ---: | ---: | --- |
| Core build and unit tests | 1 | 115 s | [Run 39054105468](https://github.com/aidangarske/himmelcloak/actions/runs/39054105468) |
| Keycloak login tests | 3 | 166 s | [Run 39054105515](https://github.com/aidangarske/himmelcloak/actions/runs/39054105515) |
| Cross-distro build and tests | 42 | 119 s | [Run 39054105459](https://github.com/aidangarske/himmelcloak/actions/runs/39054105459) |
| wolfSSL and curl compatibility | 4 | 378 s | [Run 39054105419](https://github.com/aidangarske/himmelcloak/actions/runs/39054105419) |

The required core and login workflows had a 166 s job-span envelope in this
snapshot; the native compatibility workflow took 378 s. Cargo-deny was not yet
present, so a post-change required-check baseline must be collected after the
first run. Queue time and source-event-to-run-start latency are excluded above.

`CI runtime baseline` runs after each of these four workflows completes and logs
per-job seconds, conclusion, source commit, run link, and attempt in its log and
step summary. Its workflow elapsed value is measured from GitHub's run start
through the last measured job, so it can include initial runner wait time.
It paginates jobs and selects the exact attempt. It skips cancelled runs and excludes cancelled/skipped jobs and jobs without
both timestamps. Missing run start times produce an unavailable elapsed value.
It uses read permissions and checks out only `github.workflow_sha`, the trusted
default-branch revision defining the reporting workflow, never the triggering
PR head. This also applies when the source run is a fork PR. GitHub loads
`workflow_run` workflows from the default branch, so automatic timing reports
start after this file is merged. Preserve run links when comparing future
baselines and use the same timing definition.

## Acceptance checks

1. Open a PR: all three required check names must appear.
2. On a disposable branch, add a dependency with a license outside `deny.toml`;
   verify the supply-chain check fails, then revert the dependency.
3. Use a dependency version with a current RustSec vulnerability; verify the
   advisory check fails, then revert. Do not commit an advisory ignore.
4. In a disposable workflow branch, replace only the nightly image reference
   with a nonexistent tag. Stable must still run; nightly must warn and the
   optional nightly check and workflow must fail while the required stable check
   succeeds. Confirm branch rules do not require the nightly check. Then inject a stable test failure
   and verify the workflow fails. Restore both before merge.
5. After merging, inspect the runtime workflow summary and record a post-change
   run link and required-check elapsed time here.

The negative integration checks require GitHub Actions and are not implied by
local syntax validation.

## Reporter tests

Run the committed offline fixtures with:

```sh
python3 -m unittest discover -s tests/ci -p 'test_*.py' -v
```

Core CI runs these tests before its Rust checks. Fixtures cover pagination and
exact attempts, empty first/final pages, null job/run timestamps, cancelled runs
and jobs, and pipe/newline characters in job names.
