# PAM challenge translation and configuration parsing (HC-40)

The PAM crate now contains two helpers for the Sprint 2 slice:

- `conversation::plan(&Challenge)` produces ordered PAM messages and indicates
  whether the caller needs input, acknowledgement, or a WebAuthn adapter.
- `config::ConfigDocument::load(path)` reads bounded UTF-8 TOML and rejects
  malformed syntax. The intended installed path is
  `/etc/himmelcloak/himmelcloak.toml` (`config::DEFAULT_CONFIG_PATH`).

These helpers do not invoke an application conversation callback or drive the
login engine. The exported PAM entry points still deny access by default.

## Message styles

| Challenge or event | PAM message style |
| --- | --- |
| Username or sign-in method selection | `PAM_PROMPT_ECHO_ON` (2) |
| Password, one-time code, recovery code | `PAM_PROMPT_ECHO_OFF` (1) |
| Choosing among multiple OTP devices | Visible device selection, then hidden code |
| Required-action fields | Each field's `secret` flag selects hidden or visible input |
| Information or a required-action message | `PAM_TEXT_INFO` (4) |
| WebAuthn | Information plus a marker requiring the caller's adapter; no signing here |
| Failed authentication message | `PAM_ERROR_MSG` (3), via `failure_plan` |

Information and fieldless required actions require the caller to acknowledge;
they do not automatically approve the login. Unsupported future challenges,
empty method lists, and messages containing an interior NUL are rejected.

## Configuration boundary

HC-40 checks TOML syntax; it does not establish the full shared settings schema.
For example, both a flat `realm = "test"` document and a `[keycloak]` table parse.
Unknown keys and sections are retained. A syntactically valid document can
still have invalid runtime settings and must not be used to authenticate until
those settings and identity rules have been validated in later work.

Reads are capped at 64 KiB. Missing files, invalid UTF-8, malformed TOML, and
oversized input return errors. Parser errors do not include input source lines
or their values. No configuration or PAM stack files are installed by tests.

The Tozny fork's optional `[keycloak]` typed-settings experiment remains separate
from this syntax parser. Full configuration and identity-mapping validation and
the real PAM conversation round trip belong to HC-41; engine wiring belongs to
HC-42.

## Validation

Use the prerequisites in [Getting Started](../../docs/Getting-Started.md).
From the repository root:

```bash
make test
make lint
make pam-smoke
```

`make pam-smoke` is separate from default unit tests and requires Docker and
network access. It builds and loads the denying module in a disposable Linux
container. See [the load-test instructions](tests/README.md).

## Design reference

David recommended forking [Tozny's Rust PAM project](https://github.com/tozny/toznyauth-pam).
The current-Rust scaffold in [Josh's fork](https://github.com/synod1c/toznyauth-pam)
follows its separation of PAM entry points, conversation handling, and config
parsing. The helpers here are adapted from that scaffold; the original Tozny
2015 authentication and build code is not installed or used by this crate.

Task: [HC-40 / issue #54](https://github.com/aidangarske/himmelcloak/issues/54).
