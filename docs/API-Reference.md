# API Reference

The working public entry point is `PublicClientApplication`. Construct it with the Keycloak base
URL, realm, and public client ID:

```rust
let app = PublicClientApplication::new(
    "https://keycloak.example",
    "my-realm",
    "my-public-client",
).await?;
```

For a private CA or custom timeout, create `Config` and call
`PublicClientApplication::with_config`. The library verifies the discovered issuer and requires
libcurl to report wolfSSL as its TLS backend. The Keycloak server URL must use
HTTPS, including for a server on loopback; the browser callback URI may use
loopback HTTP.

The pinned wolfSSL build verifies RS256 ID tokens with 2048-, 3072-,
or 4096-bit RSA signing keys, and ES256 tokens with P-256 keys. Its configured
RSA maximum is 4096 bits; realms using 8192-bit signing keys require a
different native wolfSSL build and verifier configuration.

Async calls require a Tokio runtime with its time driver enabled and return a
transport error when polled without either. `Config::timeout` covers both
waiting for transport capacity and the HTTP transfer.
A request that never reached Keycloak (its host name did not resolve or no connection could
be made, and nothing was sent) fails with `Error::Unreachable`, which is safe to repeat; other
network failures are `Error::Transport`. A login form post that fails with `Unreachable` is
sent once more before the error reaches the caller.
The current runtime guard requires a Rust build with `panic=unwind`; a
`panic=abort` build is rejected at compile time.

| Method | Behavior |
| --- | --- |
| `acquire_token_by_password(user, password, totp)` | Direct Access Grant when enabled on the Keycloak client and by Cargo features |
| `refresh_tokens(&tokens)` | Refresh a verified session; keep its subject when Keycloak omits a new ID token |
| `revoke_token(token)` | Revoke an access or refresh token |
| `userinfo(&tokens)` | Fetch claims and compare the subject to the verified session |

When a refresh response omits an ID token, Himmelcloak checks userinfo before
accepting the new session. If that check fails after Keycloak rotates the refresh
token, the caller must sign in again.

For a direct grant, `AuthenticationRejected` indicates rejected credentials or
access, while `InvalidConfiguration` reports a Keycloak client or grant setting
that needs operator attention.
The method returns `UnsupportedFactor` when the `password` feature is disabled
or a TOTP value is supplied without the `totp` feature.

The browser-free login is a loop: each `AuthStep` is a `Challenge` to show the user, `Complete`
with tokens, or `Failed` with Keycloak's message. The caller answers each `Challenge` with the
matching `Answer` and uses `Challenge::input()` to decide whether the prompt hides or shows what
the user types (`Input::Hidden`, `Input::Visible`, or `Input::None`). A required action returns
`Input::Form`: each of its `fields` says whether its input is secret, and the answer gives one value per field. Secret answers are wiped from
memory when dropped. `AuthFlow::cancel()` ends a login, and a login expires after
`DEFAULT_LOGIN_TIMEOUT` (30 minutes, Keycloak's default login timeout); after either, every step returns `Cancelled` or `Expired`.
An answer that does not fit the waiting challenge (the wrong kind, a device or method the page did
not offer, a WebAuthn credential outside the allow-list, or required-action fields that do not
match exactly) is refused with a protocol error before anything is sent. Any error ends the login,
and later steps then fail with `Protocol("login flow failed")`. Keycloak's username-and-password
page is handled: it asks `Username` (unless `Start::login_hint` is set) and then `Password`. A wrong
password ends the login with `AuthStep::Failed` carrying Keycloak's message, such as "Invalid
username or password."; start a new login to try again, as `login` and `sshd` do for any PAM
failure. Other pages, such as the one-time-code page, still return `UnsupportedFactor` until their
handlers land.

These types replace the earlier placeholders, which had no callers: `Challenge::Totp` and
`Answer::Totp` became `OneTimeCode`, the SMS and email variants were removed until those
Priority 2 factors are built, and `AuthFlow::default()` is gone because only
`initiate_auth_flow` creates a flow.

## Token cache

`himmelcloak::cache::TokenCache` keeps a verified session's `Tokens` across a process restart.
`TokenCache::open(dir, key_file)` creates the cache directory (mode 0700) and a random 256-bit
key (mode 0600) when they are missing; the key file's parent directory must exist. Both, and
every entry, must belong to root with no access for group or others, or the call fails with
`InvalidConfiguration`. `store(user, &tokens, expires_at)` encrypts the tokens with AES-256-GCM
and replaces that user's entry; an expiry that has already passed returns `Expired` and writes
nothing. `load(user)` returns `Ok(None)` when nothing is saved, `Expired` (and deletes the entry)
after its expiry, and `Crypto` for an entry that was altered, written under another user's name,
or sealed with a different key. `remove(user)` deletes the entry if there is one.

A cached session never grants access by itself: callers still refresh or check it with Keycloak,
and offline login stays outside scope. See [Token cache](Architecture.md#token-cache) for the
format and what it protects against.

## Read-only group sync

`himmelcloak::admin::read_allowed_group(&Config, group_id, client_secret)` uses
client credentials and returns `Vec<GroupMember>` with `id`, `username`, and
`enabled`. It reads only that group's members and returns no partial result on
failure. This service-account API is separate from `PublicClientApplication`'s
public-client login flow. See [Group sync](Getting-Started.md#group-sync) for CLI configuration and
[Group synchronization](Testing.md#group-synchronization) for the live fixture.

## Software authenticator registration

With `webauthn-virtual`, create a fresh `SoftwareAuthenticator::new(rp_id)` and
call its `WebAuthnAdapter::make_credential(&WebAuthnCreateRequest)` method.
The request carries RP and user entities, the SHA-256 hash of the exact
`clientDataJSON` being submitted, offered COSE algorithms, excluded credential
IDs, user-verification policy, and whether a resident key is required. The RP
entity contains its ID and name; the user entity contains an opaque 1–64-byte
handle, username, and display name. These inputs support CTAP and signed
attestation backends even though `none` attestation does not sign the hash.
The virtual backend requires a nonempty RP name and username and a valid user
handle. It supports ES256 (`-7`), explicit credentials, and simulated user presence. Required
UV or resident keys, or a list without ES256, returns `UnsupportedFactor`.
A mismatched RP, excluded credential, malformed exclusion list, or credential
already used for assertions or registration returns `AuthenticationRejected`.
Exclusion lists accept at most 64 descriptors, each with a 1–1023-byte ID.

Each instance permits one successful registration, independently of its
assertion counter. Failed calls leave it available for a corrected request;
a successful call consumes registration even if the caller never posts its
response. A new registration attempt after success requires a fresh instance.

`WebAuthnRegistration` contains the public credential ID and a CBOR attestation
object with format `none`. It provides no device attestation signature. The
caller builds `clientDataJSON` with the real server challenge, origin and
`webauthn.create` type and posts it with the response; the authenticator does
not parse pages or send HTTP requests. Keep the same instance for subsequent
`get_assertion` requests. Private key material never leaves the instance.
