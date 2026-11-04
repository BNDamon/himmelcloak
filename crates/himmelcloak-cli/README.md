## Test login

`himmelcloak-cli test-login` runs a native password login through the
authentication engine. It prompts for a username and a hidden password.
It requires an interactive Unix terminal.

Create or extend `himmelcloak.toml` in the current working directory:

```toml
[login]
server_url = "https://keycloak.test:8443"
realm = "himmelcloak-test"
client_id = "himmelcloak-test-client"
ca_bundle = "/absolute/path/to/tests/keycloak/.generated/ca.pem"
```

Use the server, realm, and public client configured for your deployment.
The server must use HTTPS. Omit `ca_bundle` when the server certificate
is trusted by the system. Never put the user's password in this file.

Run:

```bash
scripts/with-native.sh cargo run --locked -p himmelcloak-cli -- test-login
```

A successful login prints `himmelcloak-cli: login succeeded` and exits
with status 0. Failed logins and configuration errors exit with a
nonzero status and a fixed error message.

The command does not print or persist resulting tokens. Password input
is not echoed. Server-provided failure details are not printed.

This command currently supports username and password challenges.
Other challenges, including OTP, WebAuthn, and required actions, end
the login with an unsupported-challenge message.

### Validation

Configuration tests cover missing settings, HTTPS enforcement, optional
CA configuration, unrelated configuration tables, and error messages
that do not echo sensitive configuration values.

A live terminal test against the latest Keycloak image must also confirm
successful fixture-user login and that neither the password nor tokens
appear in command output.
