# Keycloak test oracle

The integration suite authenticates against an unmodified Keycloak container. Compose imports
`tests/keycloak/realm-export.json`, which has public OIDC clients and disposable `alice` and `passkey-test`
users. A generated test CA signs the HTTPS certificate for the `keycloak.test`
Docker network alias.

The realm also contains disposable one-time-code fixture users. `bob` has a
30-second, 6-digit SHA-1 TOTP credential. `carol` has an 8-digit SHA-256 TOTP
credential and a SHA-1 HOTP credential. `dave` has a SHA-1 HOTP-only credential
so the live suite can exercise direct-grant HOTP login. Their fixed Base32 test
secrets exist only for local and CI testing. The live suite verifies accepted
and rejected TOTP codes for Bob and Carol, plus accepted and rejected HOTP codes
for Dave. After changing `tests/keycloak/realm-export.json`, run
`make test-live` to rebuild the temporary Keycloak realm.

Run `make test-live` for the moving `latest` Keycloak image or set `KEYCLOAK_IMAGE` to another tag.
Each local run recreates the Keycloak container so realm import uses the current fixture.
Run `make oracle-down` afterward to remove the test server and its state.

Run `tests/keycloak/run.sh --verbose` (or `make test-live-verbose`) to see
Himmelcloak's client steps and Keycloak's `LOGIN`/`LOGIN_ERROR` and
`CODE_TO_TOKEN`/`CODE_TO_TOKEN_ERROR` event lines.
The trace reports outcomes and subjects but never prints passwords or tokens.
CI enables the same client trace and server event output for each live run.

The live tests are ignored by a plain `cargo test` and require `KEYCLOAK_URL`
and `KEYCLOAK_CA`; the Compose tester sets both and runs them with `--ignored`.
`browser_free_password_login` in `tests/live_keycloak.rs` drives a whole login
through the public API (`initiate_auth_flow` and `continue_auth_flow`) on the
realm's `himmelcloak-browser-only` client: Keycloak first refuses the password
grant for it, then alice signs in by answering username and password, signs in
again with a login hint that skips the username, and a wrong password ends the
login as `Failed` with Keycloak's message.
`cli_test_login_completes_a_password_login_end_to_end` in
`crates/himmelcloak-cli/tests/live_keycloak.rs` runs the real `himmelcloak-cli test-login`
binary in a pseudo-terminal on the same client: alice's username and password at its prompts
print `login succeeded` and exit 0, a wrong password prints `login failed` and exits 1, and
neither run prints the password or a token.
The suite runs `cargo test --workspace --features webauthn-virtual --lib --test live_keycloak -- --ignored`,
so it also runs every workspace crate's `live_keycloak` tests and the library's live scenarios in
`src/flow/live.rs`. Those cover the pieces
underneath the public API, such
as submitting the login form: a correct password reaches the registered callback
with a code, and a wrong one returns the login page. The code exchange scenario
redeems that code for tokens that pass the ID token checks, and a code Keycloak
never issued is rejected. They log in through the
realm's `himmelcloak-browser-only` client, which has direct grants disabled. The
completion scenario first confirms Keycloak refuses the password grant for that
client, then completes the login at the callback, so it proves the browser-free
flow works without the password grant. It then redeems the same code again with
the login's own verifier and nonce, which Keycloak refuses and answers by
revoking the session the code created. A separate scenario holds a code past
its lifespan and expects it refused. The test realm sets `accessCodeLifespan`
to 10 seconds so that scenario waits 12 seconds instead of over a minute; this
only shortens how long a code can be redeemed, in the test realm only, and real
deployments keep their own Keycloak setting.
CI runs the same test against the latest stable release tag and the `nightly`
development image on pushes to main/release branches, every PR, and manual dispatch.
Each login job resolves and records its own image digest. Nightly image resolution,
startup, and test failures produce a failed optional check, warning, and job summary
without cancelling stable login. Stable failures remain blocking. See [CI gates and runtime baseline](CI.md).
The separate native dependency matrix resolves current stable and development
refs to commit IDs before building wolfSSL and curl. The standard image uses
the wolfSSL and curl release commits pinned in `scripts/build-native.sh`. The image records
both refs and commits in `/opt/himmelcloak-native/.himmelcloak-refs`.
The dependency build disables wolfSSL's example and test executables; it builds
the library with all features and retains compiler warning checks. The compatibility
matrix still builds Himmelcloak against each dependency pair and runs its tests.
The native cache stamp includes this build mode. Existing native prefixes need a
fresh `NATIVE_PREFIX` or a rebuild when their stamp does not match.
Each new login factor must add a live scenario before its feature is treated as
complete.

The challenge/answer contract is unit-tested without a server in `src/client.rs`
and `src/flow/driver.rs`. Stub factor handlers drive recorded Keycloak pages
from `tests/fixtures/keycloak` through a username, password, and one-time-code
login to `Complete` with verified tokens. Every rejection path ends the login
before anything more is sent: a wrong answer at each step, an ended or idle
login, a time limit reached between challenges or during a request, pages and
redirects the login cannot follow, a non-200 page, another client continuing
the login, a failing handler, and a step abandoned mid-request.

The exact Cargo versions remain in `Cargo.lock` for reproducible builds.
Dependabot checks Cargo and GitHub Actions updates weekly, while the resolver
workflows expose new native and Keycloak releases immediately.

## Seeded WebAuthn credential

The `himmelcloak-webauthn` client binds a separate test flow that requires a
password followed by WebAuthn. The `passkey-test` user has a preloaded public
credential in `realm-export.json`; no key registration is performed during the
suite. Existing password-only clients retain their flows.

`software-credential.json` contains the matching disposable P-256 test key
(private scalar 1, the standard generator point), credential ID, and RP ID
`keycloak.test`. This deliberately public key material must never be used for
real accounts. Its importer is compiled only with `cfg(test)`; production
`SoftwareAuthenticator::new` always generates a fresh credential. The realm
stores only its base64url-encoded COSE public key, with ES256, no attestation,
and an initial counter of zero. A unit test checks that the fixture and realm
credential agree.

`src/flow/live_webauthn.rs` signs the actual server challenge and origin, submits
the assertion, and exchanges the callback code for verified tokens belonging
to `passkey-test`. It checks successful assertions before and after a tampered
signature, which Keycloak must refuse. Its narrow parser is test-only; it does
not implement the public WebAuthn flow driver. The normal live-suite commands
and stable/nightly CI jobs enable `webauthn-virtual` and include this scenario.
Recreate the server before rerunning: Keycloak persists the signature counter,
while a new fixture signer starts at zero.

For a targeted unit run, including malformed requests and fixture consistency:

```sh
./scripts/with-native.sh cargo test --locked --lib --features webauthn-virtual authenticator::software::tests
```

Malformed-input tests cover empty RP and credential IDs, oversized IDs, and
excessive allow lists, including malformed entries alongside a matching ID.
They also check accepted size boundaries and unchanged counters after failure.

## Group synchronization

Compose also imports `tests/keycloak/hc49-test-realm.json`, a separate disposable
realm with an allowed member, an unrelated member, a read-only service account,
and an account with no read permission. Its secrets are public test values, never
deployment credentials. The normal `make test-live` suite runs
`admin::tests::read_only_service_account_live`: it checks that only the allowed
member is returned, a user-creation attempt with the read-only account gets 403,
and the no-permission account's group read gets 403.

Injected-transport tests in `src/admin.rs` assert exact token and group-only request
paths, the client-credentials form, bearer header, and pagination offsets. They cover
empty/short/full/oversized pages, invalid inputs, query/path injection, malformed or
repeated entries, and authentication/API failures without a list-users fallback.
The CLI library's tests check sync settings and the ownership, permissions, symlink,
empty-secret and size rejection paths. They are included in the existing
`cargo test --locked --workspace --lib` CI command. Other CLI command-parsing tests
remain in its binary target and can be run with `cargo test --locked -p himmelcloak-cli`.

For a dedicated disposable local server instead of Docker, install Java 21 and
unpack a Keycloak distribution. In one terminal run:

```sh
HC49_KEYCLOAK_HOME=/path/to/disposable/keycloak bash tests/keycloak/start-hc49-local.sh
```

The script generates a short-lived localhost certificate and starts the fixture on
loopback port 18443. Use a fresh dedicated installation when changing the fixture:
startup import does not overwrite an existing realm. After it is ready, run:

```sh
HC49_KEYCLOAK_URL=https://localhost:18443 \
HC49_KEYCLOAK_CA=/tmp/himmelcloak-hc49-live/server.crt \
scripts/with-native.sh cargo test --locked -p himmelcloak --lib \
  admin::tests::read_only_service_account_live -- --ignored --exact
```

The test also accepts the normal `KEYCLOAK_URL` and `KEYCLOAK_CA` variables from
Compose. Stop the local fixture with Ctrl+C in its terminal. See the
[Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
and [server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html)
for the group-member endpoint and service-account roles.
