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
use core::fmt;

use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::flow::fetch::Redirect;
use crate::flow::{Answer, AuthFlow, AuthStep};

/// Fetch + classify the current step (the challenge to present, or completion).
pub(crate) fn step(_flow: &mut AuthFlow) -> Result<AuthStep> {
    Err(Error::NotImplemented)
}

/// Post the caller's answer to the current authenticator and advance.
pub(crate) fn advance(_flow: &mut AuthFlow, _answer: Answer) -> Result<AuthStep> {
    Err(Error::NotImplemented)
}

/// The authorization response from Keycloak's final redirect to the registered callback.
pub(crate) struct Callback {
    pub code: String,
    pub state: String,
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.code.zeroize();
        self.state.zeroize();
    }
}

impl fmt::Debug for Callback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code is a one-time credential and the state binds it to this login.
        f.debug_struct("Callback").finish_non_exhaustive()
    }
}

/// If `redirect` is Keycloak's redirect to the registered callback, return its code and state.
///
/// The callback is never fetched: this takes no transport, so recognising it cannot send a
/// request. That is why `fetch` can stay HTTPS-only while the registered callback is loopback
/// HTTP. Any other redirect returns `Ok(None)` for the driver to handle or deny.
pub(crate) fn callback(redirect: &Redirect, redirect_uri: &Url) -> Result<Option<Callback>> {
    let location = &redirect.location;
    if !same_endpoint(location, redirect_uri) {
        return Ok(None);
    }
    let mut code = None;
    let mut state = None;
    for (name, value) in location.query_pairs() {
        let slot = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            // Keycloak reports a denied or failed login as `error=...` on the callback.
            "error" => return Err(Error::AuthenticationRejected),
            _ => continue,
        };
        // Wrap the decoded value at once, so it is wiped on every path, including the early
        // return below. `replace` hands back any earlier value, which is wiped as it drops.
        let value = Zeroizing::new(value.into_owned());
        // A repeated parameter makes it ambiguous which value is meant; refuse it.
        if slot.replace(value).is_some() {
            return Err(Error::Protocol("repeated callback parameter"));
        }
    }
    match (code, state) {
        (Some(mut code), Some(mut state)) if !code.is_empty() && !state.is_empty() => {
            // Move the values out instead of copying them, so no unscrubbed copy exists.
            Ok(Some(Callback {
                code: std::mem::take(&mut *code),
                state: std::mem::take(&mut *state),
            }))
        }
        _ => Err(Error::Protocol("callback without code or state")),
    }
}

/// Exact match on scheme, credentials, host, port, and path. The query is not compared.
fn same_endpoint(location: &Url, expected: &Url) -> bool {
    location.scheme() == expected.scheme()
        && location.username() == expected.username()
        && location.password() == expected.password()
        && location.host() == expected.host()
        && location.port_or_known_default() == expected.port_or_known_default()
        && location.path() == expected.path()
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::callback;
    use crate::error::Error;
    use crate::flow::fetch::{Redirect, RedirectKind};

    const CALLBACK: &str = "http://127.0.0.1:8845/himmelcloak/callback";

    fn registered() -> Url {
        Url::parse(CALLBACK).unwrap()
    }

    fn redirect_to(location: &str) -> Redirect {
        Redirect {
            location: Url::parse(location).unwrap(),
            same_origin: false,
            kind: RedirectKind::Found,
        }
    }

    #[test]
    fn registered_callback_yields_code_and_state() {
        let location =
            format!("{CALLBACK}?state=synthetic-state&session_state=other&code=synthetic-code");
        let found = callback(&redirect_to(&location), &registered())
            .unwrap()
            .expect("the registered callback");
        assert_eq!(found.code, "synthetic-code");
        assert_eq!(found.state, "synthetic-state");
    }

    #[test]
    fn other_redirects_are_not_the_callback() {
        for location in [
            "https://127.0.0.1:8845/himmelcloak/callback?code=c&state=s",
            "http://127.0.0.1:8846/himmelcloak/callback?code=c&state=s",
            "http://localhost:8845/himmelcloak/callback?code=c&state=s",
            "http://evil.example:8845/himmelcloak/callback?code=c&state=s",
            "http://127.0.0.1:8845/himmelcloak/callback-evil?code=c&state=s",
            "http://user@127.0.0.1:8845/himmelcloak/callback?code=c&state=s",
            "https://keycloak.test:8443/realms/test/login-actions/required-action",
        ] {
            assert!(
                callback(&redirect_to(location), &registered())
                    .unwrap()
                    .is_none(),
                "{location} must not count as the callback"
            );
        }
    }

    #[test]
    fn login_errors_on_the_callback_are_rejections() {
        let location = format!("{CALLBACK}?error=access_denied&state=synthetic-state");
        assert_eq!(
            callback(&redirect_to(&location), &registered()).err(),
            Some(Error::AuthenticationRejected)
        );
    }

    #[test]
    fn malformed_callbacks_are_protocol_errors() {
        for (query, reason) in [
            ("state=s", "callback without code or state"),
            ("code=c", "callback without code or state"),
            ("code=&state=s", "callback without code or state"),
            ("code=c&code=d&state=s", "repeated callback parameter"),
            (
                "code=a&code=b%2Fsecret&state=s",
                "repeated callback parameter",
            ),
            ("code=c&state=s&state=t", "repeated callback parameter"),
        ] {
            let location = format!("{CALLBACK}?{query}");
            assert_eq!(
                callback(&redirect_to(&location), &registered()).err(),
                Some(Error::Protocol(reason)),
                "{query}"
            );
        }
    }

    #[test]
    fn debug_output_never_shows_the_code_or_state() {
        let location = format!("{CALLBACK}?code=synthetic-code&state=synthetic-state");
        let found = callback(&redirect_to(&location), &registered())
            .unwrap()
            .unwrap();
        assert_eq!(format!("{found:?}"), "Callback { .. }");
    }
}
