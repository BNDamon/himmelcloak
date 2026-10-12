/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! himmelcloak, native, no-browser authentication against Keycloak.
//!
//! Standalone Rust library for Linux applications using stock Keycloak.
//!
//! The public API and flow engine define the shape every method plugs into: changing a
//! `Challenge`/`Answer` variant, a trait signature, or `AuthStep` affects every caller. Per-method
//! modules plug in and must not modify the engine or public types. All crypto goes through `crypto`.

// Stubs are intentionally unused. Remove once modules are implemented.
#![allow(dead_code)]

#[cfg(panic = "abort")]
compile_error!("himmelcloak requires panic=unwind for Tokio time-driver detection");

pub mod authenticator;
pub mod authn;
pub mod client;
pub mod config;
pub mod error;
pub mod flow;

// Internal engine modules.
pub(crate) mod crypto;
pub(crate) mod sensitive_json;
pub(crate) mod standard;
pub(crate) mod token;
pub(crate) mod transport;

// Hardware key custody. Compiled only when a hardware/seal feature is enabled.
#[cfg(any(
    feature = "hsm-seal",
    feature = "hw-wolftpm",
    feature = "hw-wolfhsm",
    feature = "webauthn-platform"
))]
pub mod keystore;

pub use client::{PublicClientApplication, Start};
pub use error::{Error, Result};
pub use flow::{Answer, AuthFlow, AuthMethod, AuthStep, Challenge, Input, OtpDevice, Tokens};
