# Himmelcloak documentation

Himmelcloak is a standalone Rust library for native Keycloak authentication on Linux. It uses
Keycloak's OIDC APIs and a wolfSSL-backed HTTPS transport. The long-term interface is a typed,
resumable login flow for Linux applications.

## Pages

| Page | Description |
| --- | --- |
| [[Getting Started]] | Build and run a real Keycloak login test |
| [[Architecture]] | Components and flow-driver design |
| [[Development Plan]] | Core milestones and independent feature PRs |
| [[API Reference]] | Current public Rust interface |
| [[Testing]] | Docker oracle and CI gates |
| [[Project Structure]] | Workspace layout |
| [[Licensing]] | Source and combined-build terms |

The [software authenticator](Architecture.md#software-authenticator) section
describes the virtual WebAuthn adapter and its current limits.
