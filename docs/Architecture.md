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

Authorization-request construction is in place. Each login generates a
wolfCrypt-backed PKCE verifier and S256 challenge plus independent state and
nonce values. The flow retains those secrets, validates the returned state,
and wipes them when it ends. The driver fetches and classifies each returned
page, accepts a typed answer, and hands the final code to the code exchange.
The caller owns the user conversation; the library owns protocol state and
response validation.

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
30-minute time limit, completion, or a failed check ends it, wipes its cookies,
request secrets, and waiting page, and makes every later step fail with
`Cancelled`, `Expired`, or a protocol error (`login flow failed` after a failed
check). The driver checks this before every step. Only `initiate_auth_flow`
creates a flow.

The driver (`src/flow/driver.rs`) walks the login. It requests the
authorization URL, hands each recognised page to the factor handler that owns
it (`src/flow/factor.rs`), and returns that handler's challenges one at a time;
the page's form is posted once all are answered. Each answer must fit the
waiting challenge before anything is sent: the matching kind, an OTP device or
method the page offered, a WebAuthn credential from the allow-list, and exactly
the required action's fields. Keycloak's own same-origin redirects are
followed, at most five in a row. A redirect to another site, or one that would
repeat a form post (307 or 308), is refused, and the redirect to the registered
callback completes the login through the code exchange. Any refusal, error, or
step dropped mid-request ends the login as failed. No factor handler is
registered yet, so a real login stops at its first page with
`UnsupportedFactor`; the password and one-time-code handlers plug in as their
slices land.

Page fetching (`src/flow/fetch.rs`) is in place beneath the driver. Each
`AuthFlow` owns its own cookie jar, which keeps libcurl's cookie lines per exact
origin (scheme, host, and port), sends them only back to that origin, and is
zeroized when the flow is dropped. Redirects are never followed: a fetch
returns the resolved `Location` flagged same-origin or not, so the driver
decides every hop and can deny an unexpected host. Fetching is HTTPS-only. The
driver recognises the redirect to the registered callback (`Config::redirect_uri`,
loopback HTTP by default) by exact scheme, host, port, and path, checks that its
`state` matches the login's before trusting it, takes its `code`, and stops
without requesting it. A redirect URI with a query or fragment is refused.

Form submission (`src/flow/form.rs`) posts a recognised page's form back to
Keycloak. The form must use POST and post over HTTPS to the page's own site at
`login-actions/authenticate`, with exactly one non-empty `session_code`,
`execution`, `client_id`, and `tab_id` copied from the page. Only the fields
charter Table 2 lists are posted (`username`, `password`, `credentialId` on the
login page; `otp`, `selectedCredentialId` on the code page), starting from the
page's own values. An answer for a field the page lacks, a repeated answer, or a
device the page did not offer is refused before anything is sent.

Code exchange (`PublicClientApplication::exchange_code` in `src/client.rs`)
redeems the callback's code at the token endpoint as a public client, sending
`grant_type=authorization_code`, the code, the exact `redirect_uri` string the
authorization request sent, the client ID, and the login's PKCE verifier (RFC
6749 section 4.1.3, RFC 7636 section 4.5). The returned ID token must pass the
same checks as every other grant, and its `nonce` must equal the one this login
sent. Success finishes the `AuthFlow`. Any failure ends it too, because the code
is single-use, so the verifier and nonce never outlive the exchange. Keycloak's
`invalid_grant` (a wrong, expired, or reused code) is `AuthenticationRejected`.
`complete_at_callback` connects the exchange to the driver: Keycloak's redirect
to the registered callback is redeemed at once and the login becomes
`AuthStep::Complete`, while any other redirect is left for the driver. A refused
callback (wrong `state`, `access_denied`, or no code) ends the login without
redeeming anything, and replaying a callback fails because its login has ended.
The driver calls it for every redirect it receives.

For WebAuthn, the intended adapter builds client data for Keycloak's actual
origin and sends the signing request to a caller-provided authenticator. The
flow must preserve WebAuthn origin checks and use an explicit adapter contract
for USB, platform, and virtual test authenticators. Page parsing and theme
compatibility require tests against real Keycloak releases; custom-theme
independence is a design goal, not a current guarantee.

### Software authenticator

Enable `webauthn-virtual` to use
`himmelcloak::authenticator::software::SoftwareAuthenticator`. It implements
`WebAuthnAdapter` with one locally provisioned, in-memory ES256 credential bound
to an RP ID. Supply `credential_id()` in the request's allowed-credentials list;
the RP ID must match the provisioned RP. `public_key()` exports the 65-byte
uncompressed SEC1 / ANSI X9.63 P-256 public key (`0x04 || x || y`) for fixture
registration or signature verification. It is not a COSE key or registration
response.

Assertion data follows
[WebAuthn §6.1, Authenticator Data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data):
the RP ID hash, user-presence flag, and signature counter occupy 37 bytes.
Assertions use a DER-encoded P-256 ECDSA signature over
`authenticatorData || client_data_hash`, hashed with SHA-256. The counter starts
at zero and advances only after signing and encoding succeed; overflow is
rejected without changing state.

Calling the adapter simulates user presence. Required user verification returns
`UnsupportedFactor` so a caller can choose another authenticator; Preferred and
Discouraged produce UV=0. Only explicitly allowed credentials are supported.
Malformed requests are rejected before signing: the RP ID must be nonempty,
the allow list may contain at most 64 entries, and each credential ID must
contain 1–1023 bytes. Invalid entries reject the entire request even when
another entry matches; these failures leave the signature counter unchanged.
The internal `RefCell` makes the authenticator non-`Sync`; sharing it across
Tokio tasks requires a mutex around mutable credential state. Borrow conflicts
return `Crypto`. Keys and counters are lost when the instance is dropped.

Keycloak registration, attestation, persistent storage, discoverable credentials,
CTAP2 messages, and production CBOR parsing remain pending. The live test realm
preloads a disposable software credential; a test-only signer proves Keycloak
accepts its assertions and rejects tampered signatures. The production constructor
still generates a fresh key for every instance. See [Testing](Testing.md).

Unit tests check the assertion-data layout and an independently calculated RP
ID hash, verify DER signatures using the public key, reject tampering, and
exercise request validation, borrow conflicts, counter updates, and overflow.
CI runs these tests with `webauthn-virtual` enabled on pushes and pull requests.
For a local run after building the native dependencies:

```sh
./scripts/with-native.sh cargo test --locked --lib --no-default-features --features webauthn-virtual
```

The native wrapper locates the pinned wolfSSL and libcurl build. Transport tests
need permission to open loopback sockets; the live HTTPS suite also requires
Docker. See [Testing](Testing.md).

## Planned authentication methods

| Method | Intended mechanism | Current status |
| --- | --- | --- |
| Password | Direct Access Grant; later native flow | Direct grant implemented; native flow driver in place, password page handler pending; login form and code exchange live-tested with direct grants disabled |
| TOTP / HOTP | wolfCrypt HMAC generation and verification; Direct Access Grant; later native flow | SHA-1, SHA-256, and SHA-512 generation and verification implemented; Keycloak credential persistence and live TOTP fixture pending |
| WebAuthn / passkeys | Native flow and authenticator adapter | Virtual adapter and seeded live assertion fixture implemented; public native flow pending |
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
its TLS backend. The native build pins the latest stable wolfSSL and curl
releases in `scripts/build-native.sh`, and Renovate opens a pull request when
newer ones ship. himmelcloak supports only the pinned Rust toolchain, so its
`rust-version` (the minimum supported Rust) moves with each toolchain update;
those Renovate pull requests carry the `msrv` label. Future optional modules can
add wolfTPM, wolfHSM, wolfPKCS11, and wolfCOSE without coupling the baseline
OIDC client to those devices.

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
Unit tests cover token validation, transport boundaries, and the
challenge/answer contract without a server.
The live suite covers a password authorization-code login from the login form
through the code exchange to verified tokens, with direct grants disabled, and
proves Keycloak refuses a reused or stale code. It will grow to cover WebAuthn
through a virtual authenticator, recovery, and each new factor as those
implementations land. See [Testing](Testing.md).
