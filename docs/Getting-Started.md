# Getting Started

The working core currently covers OIDC discovery, password direct grant, ID-token verification,
refresh, revocation, and userinfo. The native flow driver and additional factors are in progress.

## Run the real Keycloak suite

Docker with the Compose v2 plugin and the OpenSSL command-line tool is the
simplest supported development environment:

```sh
make test-live
make oracle-down
```

This builds a Rust 1.95 test image with wolfSSL 5.9.2 and the `curl` crate linked to a wolfSSL-backed
libcurl. It generates a local test CA, starts stock Keycloak with the seeded realm, and runs real
HTTPS login tests. `KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:nightly make test-live` selects the
nightly server. CI resolves the latest stable Keycloak release and the nightly image to exact
image digests at run time, then requires both to pass on every push and PR.

On Linux, `make native` builds the same native libraries into `.native`. `make build`, `make test`,
and `make lint` use them. The local build requires Autotools, libtool, pkg-config, clang, and a
Rust 1.95 toolchain. Plain `cargo test` skips the ignored live tests;
`make test` runs unit tests plus the local integration and contract tests. Use `make test-live` for Keycloak.
The Linux native build links wolfSSL and libcurl statically so locally built
applications can run without setting a library search path. Rebuild a prefix
created by an older shared-library build before using it with this setup.

The test realm's user is `alice` with password `correct-horse-battery-staple`. These credentials
are for the disposable Docker realm only.

See [Testing](Testing.md) for the fixture and CI contract.
