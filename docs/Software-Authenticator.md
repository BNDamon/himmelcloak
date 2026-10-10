# Software authenticator (A1)

Enable `webauthn-virtual` to use
`himmelcloak::authenticator::software::SoftwareAuthenticator`.
It provisions one in-memory ES256 credential for an RP ID and implements the
existing `WebAuthnAdapter` interface. Existing assertion request and response
types are reused without changes to the flow engine.

The caller supplies the credential ID returned by `credential_id()` in the
request's allowed-credentials list. The RP ID must match the provisioned RP.
Assertions contain SHA-256 of the RP ID, the UP flag, and an incrementing
big-endian signature counter. The signature is DER-encoded ECDSA over
`authenticatorData || client_data_hash`, using P-256 and SHA-256.

This backend simulates user presence when called. It provides no user
verification: Required is rejected; Preferred and Discouraged produce UV=0.
It supports only explicit allowed credentials, not discoverable credentials.
It uses single-threaded internal state; keys and counters are lost when the
instance is dropped. Counter overflow is rejected without changing state.

Provisioning is local only. Registration with Keycloak, attestation, persistent
storage, and a live WebAuthn login fixture are not implemented in this slice.
CTAP2 messages and CBOR parsing are outside this A1 slice.

## Local checks

```sh
cargo fmt --all --check
./scripts/with-native.sh cargo clippy --locked --all-targets --all-features -- -D warnings
./scripts/with-native.sh cargo test --locked --lib --all-features
```

The native wrapper is required to locate the pinned wolfSSL and libcurl build.
Some existing transport tests open loopback sockets and require an environment
that permits that operation. The project's live HTTPS suite additionally
requires Docker; see [Testing](Testing.md).

Tests compare all 37 assertion-data bytes with the charter Tables 6 and 7,
check a known independent RP ID hash, verify returned DER signatures with a
public-key-only verifier, reject modified signed messages, and check counter
updates and overflow. Request validation covers RP and credential mismatches,
empty allow lists, and unsupported required user verification.
