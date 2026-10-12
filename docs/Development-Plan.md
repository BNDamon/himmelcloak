# Development Plan

Establish the shared library, native dependencies, and live Keycloak test gate
first. That foundation can land as one larger, structured pull request. Create
later features in focused branches from the repository's current integration
target, with a separate pull request for each. Feature pull requests should be
independent of one another. A completed method includes its implementation,
documentation, and a real Keycloak scenario in the same pull request.

## Core ownership

The core maintainer owns the public types, OIDC and flow state machine, wolfSSL
and wolfCrypt integration, protocol and security rules, and CI test contract.
This is the largest share of the work because every method builds on it. Other
contributors can own bounded features such as WebAuthn USB, a virtual
authenticator, X.509, recovery codes, or device authorization. Assign the
next feature when its core interface and Keycloak fixture are ready; these are
feature assignments, not fixed roles that all six people must work on at once.

## Core sequence

1. **Foundation:** keep the crate standalone, pin wolfSSL v5.9.2-stable and
   the official `wolfssl-wolfcrypt` crate, build libcurl with wolfSSL, and
   implement OIDC discovery, JWKS, ID-token verification, Direct Access Grant,
   refresh, revocation, and userinfo. Seed stock Keycloak in Docker and require
   live login plus a rejected-login and TLS failure case in CI. Document exactly
   which methods work.
2. **Authorization-code engine:** add PKCE, state, nonce, cookie handling,
   redirects, typed challenge classification, and code exchange. Bound response
   sizes and accepted origins. Treat flow state as secret material and define
   how a caller resumes it. Test password login through the browser flow with
   Direct Access Grants disabled.
3. **Factor interface:** stabilize `Challenge`, `Answer`, and an authenticator
   adapter interface around the working engine. Add live TOTP, required-action,
   and recovery cases one at a time. Extend the Keycloak realm fixture for each.
4. **WebAuthn core:** build correct client data for the actual Keycloak origin,
   verify the request and response bindings, and integrate the adapter with the
   flow engine. Use a virtual authenticator for every-push CI; USB and platform
   hardware are separate feature PRs.
5. **Linux login integration:** build Himmelcloak's own Linux account and login
   components on the working authentication engine. Define identity mapping,
   local session handling, and PAM/SSH test cases before enabling system login.
   Exercise console and SSH flows in disposable Linux VMs or containers.
6. **Optional backends:** implement X.509, TPM, HSM, smartcard, and COSE paths.
   Each backend gets an isolated interface, feature flag, and appropriate
   emulator or hardware test.

## Required checks

Every push and PR runs formatting, lint, unit tests, and a real HTTPS login
suite against resolved Keycloak stable and `nightly` image digests. A separate
matrix resolves current stable and development refs for wolfSSL and curl. The
standard native test image uses the pinned wolfSSL 5.9.2 baseline. A new auth feature is only
complete when the stock Keycloak oracle demonstrates its successful and
rejected paths. Hardware-dependent tests can add an emulator gate and a
separate physical-device gate when that feature arrives; neither substitutes
for the Keycloak end-to-end suite.

## Prebuilt CI image

`publish-ci-image.yml` builds the native test images from
`.github/docker/himmelcloak-ci/` for Debian 12, Ubuntu 24.04, openSUSE Leap
16.0, openSUSE Tumbleweed, SLE BCI 16.0, Rocky Linux 9, and Fedora, publishes
them as `ghcr.io/aidangarske/himmelcloak-ci:<distro>-v1` on every push to `main`
and on manual dispatch, and records each image's immutable digest in the run
summary. System packages are installed only in those Dockerfiles, never in
workflows. `cross-distro.yml` pins those digests and builds and tests each
feature set (default, none, password, gov, passwordless) inside every image on
each push and PR; adopting a new publication is a PR that bumps the digests.

Once the image is published, the every-push foundation and Keycloak jobs should pull
that digest and mount the current checkout into the container. They still
compile and test the current Rust code on every push, including real logins
against stable and nightly Keycloak, but no longer rebuild wolfSSL and curl
each time. Keep the resolved Keycloak image digests in the test record.

The moving wolfSSL/curl compatibility matrix needs freshly built native
variants. Run it on a schedule, on demand, and when native build inputs change;
it should resolve the latest stable and development refs for those runs. This
keeps the fast login gate independent of upstream native build time while
retaining compatibility coverage without manual version updates.
