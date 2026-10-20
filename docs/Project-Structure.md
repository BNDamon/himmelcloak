# Project Structure

| Location | Purpose |
| --- | --- |
| `Cargo.toml` | Workspace manifest, plus the `himmelcloak` library crate and its feature flags |
| `crates/pam_himmelcloak/` | PAM module crate; builds `libpam_himmelcloak.so`, installed as `pam_himmelcloak.so` |
| `crates/nss_himmelcloak/` | NSS module crate; builds `libnss_himmelcloak.so`, installed as `libnss_himmelcloak.so.2` |
| `LICENSE` | GNU General Public License version 3 text |
| `CONTRIBUTING.md` | Contributor setup and pull request guidelines |
| `src/` | Keycloak client and public API |
| `src/lib.rs` | Rust library entry point and public exports |
| `src/client.rs` | `PublicClientApplication`: grants, code exchange, refresh, revocation, and userinfo |
| `src/transport.rs` | HTTP boundary and wolfSSL-backed libcurl client |
| `src/crypto.rs` | wolfCrypt hashing, randomness, and signature verification |
| `src/token.rs` | OIDC metadata, JWKS, and ID-token checks |
| `src/standard.rs` | Token, revocation, and userinfo requests |
| `src/flow` | Resumable native login state and page driver |
| `src/authn` | Factor-specific handlers |
| `tests/` | Integration tests and token fixtures |
| `examples/` | Small runnable examples |
| `tests/keycloak` | Stock Keycloak realm and Docker integration suite |
| `tests/build` | Reproducible Rust and native-dependency test image |
| `docs` | Project documentation and wiki source |

The public client and flow types are owned by the core. Factor implementations attach through
typed challenges and answers; they do not redefine the state machine.
The `himmelcloak` crate exposes a Rust API. The PAM and NSS crates build the `cdylib`
modules that will export the C entry points Linux-PAM and glibc load; there are no C headers.
