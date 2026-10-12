# Keycloak test oracle

The integration suite authenticates against an unmodified Keycloak container. Compose imports
`tests/keycloak/realm-export.json`, which has a public OIDC client and the disposable `alice`
user. A generated test CA signs the HTTPS certificate for the `keycloak.test`
Docker network alias.

Run `make test-live` for the moving `latest` Keycloak image or set `KEYCLOAK_IMAGE` to another tag.
Each local run recreates the Keycloak container so realm import uses the current fixture.
Run `make oracle-down` afterward to remove the test server and its state.

Run `tests/keycloak/run.sh --verbose` (or `make test-live-verbose`) to see
Himmelcloak's client steps and Keycloak's `LOGIN`/`LOGIN_ERROR` event lines.
The trace reports outcomes and subjects but never prints passwords or tokens.
CI enables the same client trace and server event output for each live run.

The live tests are ignored by a plain `cargo test` and require `KEYCLOAK_URL`
and `KEYCLOAK_CA`; the Compose tester sets both and runs them with `--ignored`.
CI runs the same test against the latest stable release tag and the `nightly`
development image on every push and PR. CI resolves both image digests before
starting the matrix, so a run records exactly which server builds it tested.
The separate native dependency matrix resolves current stable and development
refs to commit IDs before building wolfSSL and curl. The standard image uses
the wolfSSL and curl release commits pinned in `scripts/build-native.sh`. The image records
both refs and commits in `/opt/himmelcloak-native/.himmelcloak-refs`.
Each new login factor must add a live scenario before its feature is treated as
complete.

The exact Cargo versions remain in `Cargo.lock` for reproducible builds.
Dependabot checks Cargo and GitHub Actions updates weekly, while the resolver
workflows expose new native and Keycloak releases immediately.
