# Getting Started

The working core currently covers OIDC discovery, password direct grant, ID-token verification,
refresh, revocation, and userinfo. The native flow driver and additional factors are in progress.

## CLI skeleton

The Sprint 2 (`HC-78`) `himmelcloak-cli` crate provides the initial command-line
interface skeleton. Build it from the workspace root:

```sh
cargo build --locked -p himmelcloak-cli
```

The CLI reads `himmelcloak.toml` from the directory where you run the command.
For example, create this minimal file:

```toml
realm = "himmelcloak-test"
```

Check that the file contains valid TOML:

```sh
cargo run --locked -p himmelcloak-cli -- config check
```

The following command names are available now:

```sh
cargo run --locked -p himmelcloak-cli -- test-login
cargo run --locked -p himmelcloak-cli -- sync-users
cargo run --locked -p himmelcloak-cli -- clear-state
```

At this Sprint 2 stage, `config check` validates TOML syntax only. The
`test-login`, `sync-users`, and `clear-state` commands are placeholders; their
real behavior will be implemented in later slices.

## Run the real Keycloak suite

Docker with the Compose v2 plugin and the OpenSSL command-line tool is the
simplest supported development environment:

```sh
make test-live
make oracle-down
```

This builds a test image with the pinned Rust toolchain, the pinned wolfSSL stable release, and the
`curl` crate linked to a wolfSSL-backed libcurl. It generates a local test CA, starts stock
Keycloak with the seeded realm, and runs real HTTPS login tests.
`KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:nightly make test-live` selects the nightly server. CI
resolves the latest stable Keycloak release and the nightly image to exact image digests at run
time. Stable login is required for merging; nightly failures remain visible in an optional
check without cancelling stable. See [CI gates and runtime baseline](CI.md) for triggers
and branch-rule settings.

On Linux, `make native` builds the same native libraries into `.native`. `make build`, `make test`,
and `make lint` use them. The local build requires Autotools, libtool, pkg-config, clang, and a
Rust toolchain from `rust-toolchain.toml`. Plain `cargo test` skips the ignored live tests;
`make test` runs unit tests plus the local integration and contract tests. Use `make test-live` for Keycloak.
The Linux native build links wolfSSL and libcurl statically so locally built
applications can run without setting a library search path. The static objects
are position independent (`--with-pic`) so they can also be linked into the PAM
shared module. The cache stamp records this build setting. If an existing
prefix predates it, choose a fresh prefix rather than reusing non-PIC objects:

```bash
export NATIVE_PREFIX="$PWD/target/native-pic"
make test
make lint
```

The previous native prefix is left intact. See the [PAM module notes](../crates/pam_himmelcloak/README.md)
for HC-40's message translation and configuration-parsing boundary.

The test realm's user is `alice` with password `correct-horse-battery-staple`. These credentials
are for the disposable Docker realm only.

See [Testing](Testing.md) for the fixture and CI contract.
