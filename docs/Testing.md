# Keycloak test oracle

The integration suite authenticates against an unmodified Keycloak container. Compose imports
`tests/keycloak/realm-export.json`, which has public OIDC clients and disposable `alice` and `passkey-test`
users. A generated test CA signs the HTTPS certificate for the `keycloak.test`
Docker network alias.

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
The suite runs `cargo test --features webauthn-virtual --lib --test live_keycloak -- --ignored`, so it also
runs the library's live scenarios in `src/flow/live.rs`. Those cover flow pieces
the public API cannot reach until `initiate_auth_flow` drives a whole login, such
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
its lifespan and expects it refused. A driver scenario walks alice's login
through the login driver with a stand-in password handler to `Complete`, and a
wrong password brings the login page back as a new `Username` challenge. The test realm sets `accessCodeLifespan`
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
Each new login factor must add a live scenario before its feature is treated as
complete.

The challenge/answer contract is unit-tested without a server in `src/client.rs`
and `src/flow/driver.rs`. Stub factor handlers drive recorded Keycloak pages
from `tests/fixtures/keycloak` through a username, password, and one-time-code
login to `Complete` with verified tokens. Every rejection path ends the login
before anything more is sent: a wrong answer at each step, an ended or idle
login, a time limit reached between challenges, pages and redirects the login
cannot follow, a failing handler, and a step abandoned mid-request.

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
