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
//! Flow-driver engine: fetch the current Keycloak page, classify it, advance one step.
//!
//! This is the universal engine. It walks Keycloak's browser-flow endpoints over HTTP in pure
//! Rust (no browser): GET the page, extract the core-defined form/challenge, POST the answer.
//! Theme-independent, classification keys off core field names (see `classify`), never text.
use crate::error::{Error, Result};
use crate::flow::{Answer, AuthFlow, AuthStep};

/// Fetch + classify the current step (the challenge to present, or completion).
pub(crate) fn step(flow: &mut AuthFlow) -> Result<AuthStep> {
    flow.ensure_active()?;
    Err(Error::NotImplemented)
}

/// Post the caller's answer to the current authenticator and advance.
pub(crate) fn advance(flow: &mut AuthFlow, _answer: Answer) -> Result<AuthStep> {
    flow.ensure_active()?;
    Err(Error::NotImplemented)
}
