# himmelcloak

himmelcloak is a standalone Rust library for native authentication against
self-hosted Keycloak. Linux applications can use it directly. It does not
depend on another Linux login provider or require a Keycloak server plugin.
Himmelcloak's own PAM and SSH login integration is planned, not yet implemented.
The library first uses Keycloak's standard OIDC APIs where they cover a login.
A typed, resumable flow driver is the intended path for factors that Keycloak
normally presents through its browser login pages.

The current implementation covers discovery, password direct grant, ID-token
verification, refresh, revocation, and userinfo. The native flow driver,
WebAuthn, and recovery codes are still in development.
HTTPS uses wolfSSL through libcurl, and cryptographic operations use the
official `wolfssl-wolfcrypt` Rust crate.

## Architecture

![Himmelcloak architecture: Linux applications call PublicClientApplication,
which uses the OIDC core, libcurl with wolfSSL, stock Keycloak, and wolfCrypt
for token verification. Dashed arrows mark the planned PAM/SSH integration
and native challenge flow.](docs/assets/architecture.svg)

See [Architecture](docs/Architecture.md) for the current implementation and
planned native login flow.

## Quick start

Docker with Compose v2 and the OpenSSL command-line tool provide the
reproducible build and a real Keycloak login test:

```sh
git clone https://github.com/aidangarske/himmelcloak.git
cd himmelcloak
make test-live
make oracle-down
```

The test image builds the pinned wolfSSL stable release and wolfSSL-backed libcurl, imports a
disposable realm into stock Keycloak, and runs the Rust client over HTTPS.
On Linux with the Rust toolchain pinned in `rust-toolchain.toml` and the native
build prerequisites installed:

```sh
make native
make build
make test
```

See [Getting Started](docs/Getting-Started.md) and [Testing](docs/Testing.md)
for prerequisites, configuration, and CI behavior.

## Documentation

The version-controlled pages in [`docs/`](docs/) are the primary documentation:

- [Getting Started](docs/Getting-Started.md)
- [Architecture](docs/Architecture.md)
- [Development Plan](docs/Development-Plan.md)
- [API Reference](docs/API-Reference.md)
- [Testing](docs/Testing.md)
- [Project Structure](docs/Project-Structure.md)
- [Licensing](docs/Licensing.md)

See [Contributing](CONTRIBUTING.md) to work on the project.

## License

Himmelcloak is licensed under the [GNU General Public License v3.0 or later](LICENSE)
(GPL-3.0-or-later). See [Licensing](docs/Licensing.md) for why and for dependency terms.
