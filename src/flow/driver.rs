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
pub(crate) fn step(flow: &mut AuthFlow) -> Result<AuthStep> {
    flow.ensure_active()?;
    Err(Error::NotImplemented)
}

/// Post the caller's answer to the current authenticator and advance.
pub(crate) fn advance(flow: &mut AuthFlow, _answer: Answer) -> Result<AuthStep> {
    flow.ensure_active()?;
    Err(Error::NotImplemented)
}

/// The authorization code from Keycloak's final redirect to the registered callback, after its
/// `state` was checked against the one this login sent.
pub(crate) struct Callback {
    pub code: String,
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

impl fmt::Debug for Callback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code is a one-time credential.
        f.debug_struct("Callback").finish_non_exhaustive()
    }
}

/// If `redirect` is Keycloak's redirect to the registered callback, return its code.
///
/// The callback is never fetched: this takes no transport, so recognising it cannot send a
/// request. That is why `fetch` can stay HTTPS-only while the registered callback is loopback
/// HTTP. Any other redirect returns `Ok(None)` for the driver to handle or deny.
///
/// Every callback, including an error response, must carry the `state` this login sent
/// (`expected_state`) before anything else in it is trusted (RFC 6749 sections 4.1.2 and
/// 4.1.2.1). Only `error=access_denied` is a rejection; any other error is a protocol fault.
pub(crate) fn callback(
    redirect: &Redirect,
    redirect_uri: &Url,
    expected_state: &str,
) -> Result<Option<Callback>> {
    let location = &redirect.location;
    if !same_endpoint(location, redirect_uri) {
        return Ok(None);
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (name, value) in location.query_pairs() {
        let slot = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
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
    // The state proves this response belongs to this login; without it, anyone able to trigger a
    // redirect could end or hijack the flow.
    let state_matches = state
        .as_ref()
        .is_some_and(|state| !expected_state.is_empty() && state.as_str() == expected_state);
    if !state_matches {
        return Err(Error::Protocol("callback state mismatch"));
    }
    if let Some(error) = error {
        // Only the user or Keycloak refusing the login is a rejection; anything else is a fault.
        return Err(match error.as_str() {
            "access_denied" => Error::AuthenticationRejected,
            _ => Error::Protocol("authorization error on callback"),
        });
    }
    match code {
        // Move the value out instead of copying it, so no unscrubbed copy exists.
        Some(mut code) if !code.is_empty() => Ok(Some(Callback {
            code: std::mem::take(&mut *code),
        })),
        _ => Err(Error::Protocol("callback without code")),
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

    use super::{callback, Callback};
    use crate::error::{Error, Result};
    use crate::flow::fetch::{Redirect, RedirectKind};

    const CALLBACK: &str = "http://127.0.0.1:8845/himmelcloak/callback";
    const STATE: &str = "synthetic-state";

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

    fn at_callback(query: &str) -> Result<Option<Callback>> {
        callback(
            &redirect_to(&format!("{CALLBACK}?{query}")),
            &registered(),
            STATE,
        )
    }

    #[test]
    fn registered_callback_yields_the_code() {
        let found = at_callback("state=synthetic-state&session_state=other&code=synthetic-code")
            .unwrap()
            .expect("the registered callback");
        assert_eq!(found.code, "synthetic-code");
    }

    #[test]
    fn a_missing_or_wrong_state_is_refused_even_on_errors() {
        for query in [
            "code=c&state=other-state",
            "code=c&state=",
            "code=c",
            "error=access_denied&state=other-state",
            "error=access_denied",
        ] {
            assert_eq!(
                at_callback(query).err(),
                Some(Error::Protocol("callback state mismatch")),
                "{query}"
            );
        }
        // An empty expected state never matches, even an empty returned one.
        assert_eq!(
            callback(
                &redirect_to(&format!("{CALLBACK}?code=c&state=")),
                &registered(),
                ""
            )
            .err(),
            Some(Error::Protocol("callback state mismatch"))
        );
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
                callback(&redirect_to(location), &registered(), "s")
                    .unwrap()
                    .is_none(),
                "{location} must not count as the callback"
            );
        }
    }

    #[test]
    fn only_access_denied_is_a_rejection() {
        assert_eq!(
            at_callback("error=access_denied&state=synthetic-state").err(),
            Some(Error::AuthenticationRejected)
        );
        for query in [
            "error=server_error&state=synthetic-state",
            "error=temporarily_unavailable&state=synthetic-state",
            "error=&state=synthetic-state",
        ] {
            assert_eq!(
                at_callback(query).err(),
                Some(Error::Protocol("authorization error on callback")),
                "{query}"
            );
        }
    }

    #[test]
    fn malformed_callbacks_are_protocol_errors() {
        for (query, reason) in [
            ("state=synthetic-state", "callback without code"),
            ("code=&state=synthetic-state", "callback without code"),
            (
                "code=c&code=d&state=synthetic-state",
                "repeated callback parameter",
            ),
            (
                "code=a&code=b%2Fsecret&state=synthetic-state",
                "repeated callback parameter",
            ),
            (
                "code=c&state=synthetic-state&state=t",
                "repeated callback parameter",
            ),
            (
                "error=access_denied&error=server_error&state=synthetic-state",
                "repeated callback parameter",
            ),
        ] {
            assert_eq!(
                at_callback(query).err(),
                Some(Error::Protocol(reason)),
                "{query}"
            );
        }
    }

    #[test]
    fn debug_output_never_shows_the_code() {
        let found = at_callback("code=synthetic-code&state=synthetic-state")
            .unwrap()
            .unwrap();
        assert_eq!(format!("{found:?}"), "Callback { .. }");
    }
}
