# Architecture

Himmelcloak is a standalone Rust client for stock Keycloak. Applications call
its public API directly; the library owns the Keycloak protocol and token
validation.

![Himmelcloak architecture: Linux applications call PublicClientApplication,
which uses the OIDC core, libcurl with wolfSSL, stock Keycloak, and wolfCrypt
for token verification. Dashed arrows mark the planned PAM/SSH integration
and native challenge flow.](assets/architecture.svg)

## Current baseline

The implemented fast path discovers OIDC metadata and signing keys, performs a
Direct Access Grant with a username, password, and optional TOTP value, and
verifies the returned ID token before exposing it to callers. It also supports
refresh, revocation, and userinfo. TLS peer and hostname verification are
required. The runtime checks that libcurl is using the wolfSSL backend.

The public client accepts a Keycloak base URL, realm, and public client ID.
Direct Access Grants must be enabled for that client. A real Keycloak container
with an imported test realm exercises this path in CI. Direct grant is an
optional Keycloak configuration, so it cannot serve as the only login path.

## Native flow driver

The next core component will initiate Keycloak's authorization-code flow with
PKCE, preserve its session cookies, classify the returned challenge, accept a
typed answer, and exchange the final code for tokens. The caller owns the user
conversation; the library owns protocol state and response validation.

The challenge/answer contract in `src/flow/mod.rs` fixes that conversation.
Each Keycloak login page yields a `Challenge` (username, password, one-time
code with its device list, recovery code, WebAuthn, method choice, required
action, or info), and the caller replies with the matching `Answer`. On the
combined username-and-password page the username comes from `Start::login_hint`;
without one the flow asks `Username`, then `Password`, and posts the form once.
Required actions carry their display text and fields; actions that need
browser-only setup, such as configuring an authenticator app, are unsupported. Each
`AuthStep` is another challenge, `Complete` with tokens, or `Failed` with
Keycloak's message. `Challenge::input()` tells the caller whether to hide or
show what the user types. An `AuthFlow` is single-use: `cancel()`, a
30-minute time limit, or completion ends it, wipes its cookies, and makes
every later step fail with `Cancelled`, `Expired`, or a protocol error. The
driver checks this before every step. Only `initiate_auth_flow` creates a flow.
`initiate_auth_flow` and `continue_auth_flow` otherwise still return
`NotImplemented`.

Page fetching (`src/flow/fetch.rs`) is in place beneath the driver. Each
`AuthFlow` owns its own cookie jar, which keeps libcurl's cookie lines per exact
origin (scheme, host, and port), sends them only back to that origin, and is
zeroized when the flow is dropped. Redirects are never followed: a fetch
returns the resolved `Location` flagged same-origin or not, so the driver
decides every hop and can deny an unexpected host.

For WebAuthn, the intended adapter builds client data for Keycloak's actual
origin and sends the signing request to a caller-provided authenticator. The
flow must preserve WebAuthn origin checks and use an explicit adapter contract
for USB, platform, and virtual test authenticators. Page parsing and theme
compatibility require tests against real Keycloak releases; custom-theme
independence is a design goal, not a current guarantee.

## Planned authentication methods

| Method | Intended mechanism | Current status |
| --- | --- | --- |
| Password | Direct Access Grant; later native flow | Direct grant implemented |
| TOTP | Direct Access Grant; later native flow | Optional direct-grant field implemented; live TOTP fixture pending |
| WebAuthn / passkeys | Native flow and authenticator adapter | Planned |
| SMS / email OTP | Native flow | Planned |
| Recovery codes | Native flow | Planned |
| X.509 / PIV / CAC | Mutual TLS and Keycloak flow | Planned |
| Required actions | Native flow | Planned |
| Device authorization | OIDC device endpoint | Planned |

Feature flags for later methods reserve the additive feature graph. They do
not yet imply that those methods work. The default flags are `password` and
`totp`: disabling `password` disables the direct grant, and disabling `totp`
rejects its OTP parameter. Cargo features are additive; use
`--no-default-features --features gov` or
`--no-default-features --features passwordless` to omit password support.

## Crypto and hardware boundaries

The official `wolfssl-wolfcrypt` crate supplies the cryptographic primitives
used by the core. The Rust `curl` crate drives libcurl, built with wolfSSL as
its TLS backend. The native build pins wolfSSL v5.9.2-stable. Future optional
modules can add wolfTPM, wolfHSM, wolfPKCS11, and wolfCOSE without coupling the
baseline OIDC client to those devices.

A shared limit allows up to 32 concurrent libcurl transfers per process.
Cancelling a queued request releases its slot; a running libcurl transfer
keeps its slot until it exits.

Request bodies are streamed from zeroizing Rust buffers into libcurl. libcurl
may still hold transient copies of sent bytes, and its HTTP header list copies
bearer tokens into native memory. Rust buffer cleanup cannot erase those native
copies. Treat process memory and core dumps as sensitive while the client is
running.

The source is licensed under GPL-3.0-or-later because it links GPL wolfSSL
components. See [Licensing](Licensing.md) for details.

## Test contract

Every completed method needs a live test against an unmodified Keycloak
container. CI resolves the latest stable release and `nightly` image digests,
then runs the same integration suite against both.
Unit tests cover token validation and transport boundaries without a server.
The live suite will grow to cover authorization-code login, WebAuthn through a
virtual authenticator, recovery, and each new factor as those implementations
land. See [Testing](Testing.md).
