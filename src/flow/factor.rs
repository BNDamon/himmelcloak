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
//! Factor handlers: how a recognised Keycloak page becomes challenges, and how the caller's
//! answers become that page's form fields. Each login factor plugs in here; the driver owns
//! everything else (fetching, redirects, answer checks, the callback, and the lifecycle).
use zeroize::Zeroizing;

use crate::error::Result;
use crate::flow::classify::PageKind;
use crate::flow::{Answer, Challenge};

/// One factor's handling of the pages it owns.
pub(crate) trait PageFactor: Send + Sync {
    /// The challenges this page asks, in order. The form is posted once all are answered.
    /// `login_hint` is `Start::login_hint`, which Keycloak already filled in as the username.
    fn challenges(&self, kind: &PageKind, login_hint: Option<&str>) -> Result<Vec<Challenge>>;

    /// The form fields to post. `answers` come in the order `challenges` asked them, and each
    /// already matched its challenge.
    fn fields(
        &self,
        kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>>;
}

/// Which factor handles a page.
pub(crate) trait Factors: Send + Sync {
    fn for_page(&self, kind: &PageKind) -> Option<&dyn PageFactor>;
}

/// The factors this build handles. A page without one ends the login with `UnsupportedFactor`.
pub(crate) struct Builtin;

impl Factors for Builtin {
    fn for_page(&self, _kind: &PageKind) -> Option<&dyn PageFactor> {
        // The password and one-time-code handlers register here as their slices land.
        None
    }
}
