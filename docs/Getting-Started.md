# Getting Started

The working core currently covers OIDC discovery, password direct grant, ID-token verification,
refresh, revocation, and userinfo. The native flow driver and additional factors are in progress.

## CLI administration

The `himmelcloak-cli` workspace crate provides the administrator command-line
interface. Build it from the workspace root:

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

`config check` validates TOML syntax only. `clear-state` remains a placeholder.
`test-login` runs an interactive native password login. `sync-users` reads the
configured group as described below.

### Test login

Add a `[login]` table to `himmelcloak.toml` in the directory where you run
the CLI. Existing tables, including `[sync]`, can remain in the file.

```toml
[login]
server_url = "https://keycloak.example.org"
realm = "example"
client_id = "linux-login"
# ca_bundle = "/absolute/path/to/private-keycloak-ca.pem"
```

Use a public client with the standard authorization-code flow enabled and
this allowed redirect URI:

```text
http://127.0.0.1:8845/himmelcloak/callback
```

Direct access grants are not required. The server URL must use HTTPS.
Set `ca_bundle` when the certificate requires a private CA; otherwise omit it.

From the repository root, build using the native environment:

```sh
scripts/with-native.sh cargo build --locked -p himmelcloak-cli
```

From the directory containing `himmelcloak.toml`, run:

```sh
/absolute/path/to/target/debug/himmelcloak-cli test-login
```

Enter the username and password when prompted. Password input requires an
interactive Unix terminal and is not echoed. Do not put the password in
configuration files or command arguments.

Success prints `himmelcloak-cli: login succeeded` and exits with status 0.
Errors exit nonzero with a fixed message. Tokens and server-provided error
details are not printed, and resulting tokens are not persisted.

The command currently handles username and password challenges. OTP,
WebAuthn, and required-action challenges are not supported by this command.

The interrupt handler attempts to restore terminal settings before exiting
with status 130 on Ctrl+C, SIGTERM, or SIGHUP.

### Group sync

Build using the project's native dependencies, then run the CLI as root from a
trusted configuration directory. The command reads `himmelcloak.toml` in that
directory, following the existing CLI configuration-file behavior. Add:

```toml
[sync]
server_url = "https://keycloak.example.org"
realm = "example"
client_id = "linux-sync"
allowed_group_id = "11111111-1111-4111-8111-111111111111"
client_secret_file = "/etc/himmelcloak/admin-client.secret"
# ca_bundle = "/etc/ssl/certs/private-keycloak-ca.pem"
```

The server URL is the base URL before `/realms/<realm>` and may include a deployment
prefix such as `/auth`. The group is an exact ID, not a group-name search.
Provision a confidential client with service accounts enabled and read-only
member access; disable its browser and password grants. Do not grant `manage-users`
or `realm-admin`. The [architecture](Architecture.md#nss-group-synchronization)
explains the fixture's read-only role and its limitations.

The config must be a root-owned regular file without group/other write access
and no larger than 64 KiB. The secret must be a separate root-owned regular file
with mode 0600 or 0400 and no larger than 16 KiB. Both reject symlinks. File paths
inside `[sync]` must be absolute; a trailing CR/LF is trimmed from the secret.
Only the `[sync]` table receives typed validation here; `config check` retains
its existing syntax-only behavior. Use your secret-provisioning process to create
the real secret file, and never put the secret in command arguments or source control.

```sh
# Build at the repository root with the native build environment configured.
scripts/with-native.sh cargo build --locked -p himmelcloak-cli

# From the trusted directory containing himmelcloak.toml:
sudo /absolute/path/to/target/debug/himmelcloak-cli sync-users
```

Success returns a JSON array of `{id, username, enabled}` objects. Failure exits
nonzero with no partial JSON and no fallback to listing all users. Local account-file
writing and system-login integration are not implemented by this stage.

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
