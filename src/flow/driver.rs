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
use std::collections::VecDeque;

use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::client::{PublicClientApplication, Start};
use crate::error::{Error, Result};
use crate::flow::classify::PageKind;
use crate::flow::factor::Factors;
use crate::flow::fetch::{self, Fetched, Page, Redirect};
use crate::flow::form::{self, Form};
use crate::flow::{Answer, AuthFlow, AuthStep, Challenge};

/// Same-origin redirects followed between two pages before the login is refused.
const MAX_REDIRECTS: usize = 5;

/// The page waiting on the caller: its form, the challenge being answered, the challenges still
/// to ask, and the answers so far.
pub(crate) struct Pending {
    kind: PageKind,
    form: Form,
    expect: Expect,
    queue: VecDeque<Challenge>,
    answers: Vec<Answer>,
}

/// Start the login: fetch Keycloak's first page and return what it asks.
pub(crate) async fn begin(
    app: &PublicClientApplication,
    factors: &dyn Factors,
    start: &Start,
    flow: &mut AuthFlow,
) -> Result<AuthStep> {
    let mut step = Step { flow, done: false };
    let next = first_page(app, factors, start, step.flow).await;
    step.done = next.is_ok();
    next
}

/// Check the caller's answer against the waiting challenge, then ask the page's next challenge
/// or post its form and move on.
pub(crate) async fn advance(
    app: &PublicClientApplication,
    factors: &dyn Factors,
    flow: &mut AuthFlow,
    answer: Answer,
) -> Result<AuthStep> {
    let mut step = Step { flow, done: false };
    let next = answer_page(app, factors, step.flow, answer).await;
    step.done = next.is_ok();
    next
}

/// Fails the login unless the step succeeds. A step that errors or is dropped mid-request leaves
/// Keycloak's side of the login unknown, so it cannot be resumed.
struct Step<'a> {
    flow: &'a mut AuthFlow,
    done: bool,
}

impl Drop for Step<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.flow.fail();
        }
    }
}

async fn first_page(
    app: &PublicClientApplication,
    factors: &dyn Factors,
    start: &Start,
    flow: &mut AuthFlow,
) -> Result<AuthStep> {
    let url = app.authorization_url(start, flow)?;
    let fetched = fetch::get(app.transport(), &mut flow.jar, url).await?;
    resolve(app, factors, flow, fetched).await
}

async fn answer_page(
    app: &PublicClientApplication,
    factors: &dyn Factors,
    flow: &mut AuthFlow,
    answer: Answer,
) -> Result<AuthStep> {
    flow.ensure_active()?;
    let mut pending = flow
        .pending
        .take()
        .ok_or(Error::Protocol("no challenge is waiting for an answer"))?;
    pending.expect.check(&answer)?;
    pending.answers.push(answer);
    if let Some(next) = pending.queue.pop_front() {
        pending.expect = Expect::of(&next);
        flow.pending = Some(pending);
        return Ok(AuthStep::Challenge(next));
    }
    let factor = factors
        .for_page(&pending.kind)
        .ok_or(Error::UnsupportedFactor)?;
    let fields = factor.fields(&pending.kind, &pending.answers)?;
    let fields: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let fetched = pending
        .form
        .submit(app.transport(), &mut flow.jar, &fields)
        .await?;
    resolve(app, factors, flow, fetched).await
}

/// Turn Keycloak's response into the next step: a page's first challenge, or completion at the
/// callback. Keycloak's own same-origin redirects are followed; any other redirect is refused.
async fn resolve(
    app: &PublicClientApplication,
    factors: &dyn Factors,
    flow: &mut AuthFlow,
    mut fetched: Fetched,
) -> Result<AuthStep> {
    let mut followed = 0;
    loop {
        let redirect = match fetched {
            Fetched::Page(page) => return present(factors, flow, &page),
            Fetched::Redirect(redirect) => redirect,
        };
        if let Some(complete) = app.complete_at_callback(&redirect, flow).await? {
            return Ok(complete);
        }
        // A 307 or 308 would repeat the form post to wherever it points.
        if !redirect.same_origin || redirect.kind.repeats_request() {
            return Err(Error::Protocol("unexpected redirect"));
        }
        if followed == MAX_REDIRECTS {
            return Err(Error::Protocol("too many redirects"));
        }
        followed += 1;
        fetched = fetch::get(app.transport(), &mut flow.jar, redirect.location.clone()).await?;
    }
}

/// Hand the page to its factor and return the page's first challenge.
fn present(factors: &dyn Factors, flow: &mut AuthFlow, page: &Page) -> Result<AuthStep> {
    let (kind, form) = form::extract(page)?;
    let factor = factors.for_page(&kind).ok_or(Error::UnsupportedFactor)?;
    let mut queue = VecDeque::from(factor.challenges(&kind)?);
    let first = queue
        .pop_front()
        .ok_or(Error::Protocol("page asks no challenge"))?;
    flow.pending = Some(Pending {
        kind,
        form,
        expect: Expect::of(&first),
        queue,
        answers: Vec::new(),
    });
    Ok(AuthStep::Challenge(first))
}

/// What the waiting challenge accepts, kept because the `Challenge` itself goes to the caller.
enum Expect {
    Username,
    Password,
    OneTimeCode { devices: Vec<String> },
    RecoveryCode,
    WebAuthn { allowed: Vec<Vec<u8>> },
    ChooseMethod { methods: Vec<String> },
    RequiredAction { fields: Vec<String> },
    Info,
}

impl Expect {
    fn of(challenge: &Challenge) -> Self {
        match challenge {
            Challenge::Username => Self::Username,
            Challenge::Password => Self::Password,
            Challenge::OneTimeCode { devices } => Self::OneTimeCode {
                devices: devices.iter().map(|device| device.id.clone()).collect(),
            },
            Challenge::RecoveryCode { .. } => Self::RecoveryCode,
            Challenge::WebAuthn(request) => Self::WebAuthn {
                allowed: request
                    .allow_credentials
                    .iter()
                    .map(|credential| credential.id.clone())
                    .collect(),
            },
            Challenge::ChooseMethod { methods } => Self::ChooseMethod {
                methods: methods.iter().map(|method| method.id.clone()).collect(),
            },
            Challenge::RequiredAction(action) => Self::RequiredAction {
                fields: action
                    .fields
                    .iter()
                    .map(|field| field.name.clone())
                    .collect(),
            },
            Challenge::Info { .. } => Self::Info,
        }
    }

    /// Refuse an answer the waiting challenge did not ask for, before anything is sent.
    fn check(&self, answer: &Answer) -> Result<()> {
        let mismatch = Error::Protocol("answer does not match the challenge");
        match (self, answer) {
            (Self::Username, Answer::Username(_))
            | (Self::Password, Answer::Password(_))
            | (Self::RecoveryCode, Answer::RecoveryCode(_))
            | (Self::Info, Answer::Acknowledge) => Ok(()),
            // With one device the page offers no choice; with several, the caller must pick one.
            (Self::OneTimeCode { devices }, Answer::OneTimeCode { device, .. }) => match device {
                None if devices.is_empty() => Ok(()),
                None => Err(mismatch),
                Some(device) if devices.contains(device) => Ok(()),
                Some(_) => Err(Error::Protocol("device not offered by the page")),
            },
            // An empty allow-list lets the authenticator choose a discoverable credential.
            (Self::WebAuthn { allowed }, Answer::WebAuthn(assertion)) => {
                if allowed.is_empty() || allowed.contains(&assertion.credential_id) {
                    Ok(())
                } else {
                    Err(Error::Protocol("credential not allowed"))
                }
            }
            (Self::ChooseMethod { methods }, Answer::ChooseMethod(method)) => {
                if methods.contains(method) {
                    Ok(())
                } else {
                    Err(Error::Protocol("method not offered"))
                }
            }
            (Self::RequiredAction { fields }, Answer::RequiredAction(given)) => {
                let answered_once = |field: &String| {
                    given
                        .values
                        .iter()
                        .filter(|(name, _)| name == field)
                        .count()
                        == 1
                };
                if given.values.len() == fields.len() && fields.iter().all(answered_once) {
                    Ok(())
                } else {
                    Err(Error::Protocol("answer does not match the required action"))
                }
            }
            _ => Err(mismatch),
        }
    }
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
/// before anything else in it is trusted (RFC 6749 sections 4.1.2 and
/// 4.1.2.1). Only `error=access_denied` is a rejection; any other error is a protocol fault.
pub(crate) fn callback(
    redirect: &Redirect,
    redirect_uri: &Url,
    flow: &mut AuthFlow,
) -> Result<Option<Callback>> {
    let location = &redirect.location;
    if !same_endpoint(location, redirect_uri) {
        return Ok(None);
    }
    flow.ensure_active()?;
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
    let state_matches = state.as_ref().is_some_and(|state| {
        !flow.oauth_state().is_empty() && state.as_str() == flow.oauth_state()
    });
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
    use std::time::Duration;

    use url::Url;

    use super::{callback, Callback, Expect};
    use crate::authenticator::{
        CredentialDescriptor, UserVerification, WebAuthnAssertion, WebAuthnChallenge,
    };
    use crate::error::{Error, Result};
    use crate::flow::fetch::{Redirect, RedirectKind};
    use crate::flow::{
        Answer, AuthFlow, AuthMethod, Challenge, Field, OtpDevice, RequiredAction,
        RequiredActionAnswer,
    };

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

    fn new_flow() -> AuthFlow {
        AuthFlow::new(Duration::from_secs(60)).unwrap()
    }

    fn at_callback(query: &str, flow: &mut AuthFlow) -> Result<Option<Callback>> {
        callback(
            &redirect_to(&format!("{CALLBACK}?{query}")),
            &registered(),
            flow,
        )
    }

    #[test]
    fn registered_callback_yields_the_code() {
        let mut flow = new_flow();
        let state = flow.oauth_state().to_owned();
        let found = at_callback(
            &format!("state={state}&session_state=other&code=synthetic-code"),
            &mut flow,
        )
        .unwrap()
        .expect("the registered callback");
        assert_eq!(found.code, "synthetic-code");
    }

    #[test]
    fn a_missing_or_wrong_state_is_refused_even_on_errors() {
        let mut flow = new_flow();
        for query in [
            "code=c&state=other-state",
            "code=c&state=",
            "code=c",
            "error=access_denied&state=other-state",
            "error=access_denied",
        ] {
            assert_eq!(
                at_callback(query, &mut flow).err(),
                Some(Error::Protocol("callback state mismatch")),
                "{query}"
            );
        }
        // Ending a flow rejects the callback before any returned parameter is trusted.
        let mut ended = new_flow();
        ended.cancel();
        assert_eq!(
            callback(
                &redirect_to(&format!("{CALLBACK}?code=c&state=")),
                &registered(),
                &mut ended
            )
            .err(),
            Some(Error::Cancelled)
        );
    }

    #[test]
    fn other_redirects_are_not_the_callback() {
        let mut flow = new_flow();
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
                callback(&redirect_to(location), &registered(), &mut flow)
                    .unwrap()
                    .is_none(),
                "{location} must not count as the callback"
            );
        }
    }

    #[test]
    fn only_access_denied_is_a_rejection() {
        let mut flow = new_flow();
        let state = flow.oauth_state().to_owned();
        assert_eq!(
            at_callback(&format!("error=access_denied&state={state}"), &mut flow).err(),
            Some(Error::AuthenticationRejected)
        );
        for error in ["server_error", "temporarily_unavailable", ""] {
            let query = format!("error={error}&state={state}");
            assert_eq!(
                at_callback(&query, &mut flow).err(),
                Some(Error::Protocol("authorization error on callback")),
                "{query}"
            );
        }
    }

    #[test]
    fn malformed_callbacks_are_protocol_errors() {
        let mut flow = new_flow();
        let state = flow.oauth_state().to_owned();
        for (query, reason) in [
            (format!("state={state}"), "callback without code"),
            (format!("code=&state={state}"), "callback without code"),
            (
                format!("code=c&code=d&state={state}"),
                "repeated callback parameter",
            ),
            (
                format!("code=a&code=b%2Fsecret&state={state}"),
                "repeated callback parameter",
            ),
            (
                format!("code=c&state={state}&state=t"),
                "repeated callback parameter",
            ),
            (
                format!("error=access_denied&error=server_error&state={state}"),
                "repeated callback parameter",
            ),
        ] {
            assert_eq!(
                at_callback(&query, &mut flow).err(),
                Some(Error::Protocol(reason)),
                "{query}"
            );
        }
    }

    #[test]
    fn debug_output_never_shows_the_code() {
        let mut flow = new_flow();
        let state = flow.oauth_state().to_owned();
        let found = at_callback(&format!("code=synthetic-code&state={state}"), &mut flow)
            .unwrap()
            .unwrap();
        assert_eq!(format!("{found:?}"), "Callback { .. }");
    }

    #[test]
    fn expired_flow_cannot_accept_a_callback() {
        let mut flow = AuthFlow::new(Duration::ZERO).unwrap();
        let state = flow.oauth_state().to_owned();
        assert_eq!(
            at_callback(&format!("code=c&state={state}"), &mut flow).err(),
            Some(Error::Expired)
        );
    }

    fn code(device: Option<&str>) -> Answer {
        Answer::OneTimeCode {
            code: "123456".to_owned(),
            device: device.map(str::to_owned),
        }
    }

    fn devices(ids: &[&str]) -> Challenge {
        Challenge::OneTimeCode {
            devices: ids
                .iter()
                .map(|id| OtpDevice::new((*id).to_owned(), "Phone".to_owned()))
                .collect(),
        }
    }

    fn webauthn(allowed: &[&[u8]]) -> Challenge {
        Challenge::WebAuthn(WebAuthnChallenge {
            rp_id: "keycloak.test".to_owned(),
            challenge: vec![1, 2, 3],
            allow_credentials: allowed
                .iter()
                .map(|id| CredentialDescriptor { id: id.to_vec() })
                .collect(),
            user_verification: UserVerification::Preferred,
            origin: "https://keycloak.test:8443".to_owned(),
        })
    }

    fn assertion(credential_id: &[u8]) -> Answer {
        Answer::WebAuthn(WebAuthnAssertion {
            authenticator_data: Vec::new(),
            signature: Vec::new(),
            credential_id: credential_id.to_vec(),
            user_handle: None,
        })
    }

    fn methods() -> Challenge {
        Challenge::ChooseMethod {
            methods: vec![AuthMethod::new(
                "otp".to_owned(),
                "Authenticator".to_owned(),
            )],
        }
    }

    fn update_password() -> Challenge {
        let field = |name: &str| Field::new(name.to_owned(), name.to_owned(), true);
        Challenge::RequiredAction(RequiredAction::new(
            "UPDATE_PASSWORD".to_owned(),
            None,
            vec![field("password-new"), field("password-confirm")],
        ))
    }

    fn filled(names: &[&str]) -> Answer {
        Answer::RequiredAction(RequiredActionAnswer::new(
            names
                .iter()
                .map(|name| ((*name).to_owned(), "new-secret".to_owned()))
                .collect(),
        ))
    }

    #[test]
    fn every_answer_must_fit_its_challenge() {
        let mismatch = Error::Protocol("answer does not match the challenge");
        let wrong_device = Error::Protocol("device not offered by the page");
        let wrong_fields = Error::Protocol("answer does not match the required action");
        let cases = [
            (
                Challenge::Username,
                Answer::Username("alice".to_owned()),
                None,
            ),
            (Challenge::Password, Answer::Password("pw".to_owned()), None),
            (
                Challenge::RecoveryCode { index_hint: None },
                Answer::RecoveryCode("recovery".to_owned()),
                None,
            ),
            (
                Challenge::Info {
                    message: "Check your email".to_owned(),
                },
                Answer::Acknowledge,
                None,
            ),
            (
                Challenge::Password,
                Answer::Acknowledge,
                Some(mismatch.clone()),
            ),
            (
                Challenge::Username,
                Answer::Password("pw".to_owned()),
                Some(mismatch.clone()),
            ),
            (devices(&[]), code(None), None),
            (
                devices(&[]),
                code(Some("phone")),
                Some(wrong_device.clone()),
            ),
            (devices(&["phone", "tablet"]), code(Some("tablet")), None),
            (
                devices(&["phone", "tablet"]),
                code(Some("laptop")),
                Some(wrong_device),
            ),
            (
                devices(&["phone", "tablet"]),
                code(None),
                Some(mismatch.clone()),
            ),
            (webauthn(&[]), assertion(b"any-key"), None),
            (webauthn(&[b"key"]), assertion(b"key"), None),
            (
                webauthn(&[b"key"]),
                assertion(b"other-key"),
                Some(Error::Protocol("credential not allowed")),
            ),
            (methods(), Answer::ChooseMethod("otp".to_owned()), None),
            (
                methods(),
                Answer::ChooseMethod("sms".to_owned()),
                Some(Error::Protocol("method not offered")),
            ),
            (
                update_password(),
                filled(&["password-confirm", "password-new"]),
                None,
            ),
            (
                update_password(),
                filled(&["password-new"]),
                Some(wrong_fields.clone()),
            ),
            (
                update_password(),
                filled(&["password-new", "password-new"]),
                Some(wrong_fields.clone()),
            ),
            (
                update_password(),
                filled(&["password-new", "password-confirm", "username"]),
                Some(wrong_fields),
            ),
            (update_password(), Answer::Acknowledge, Some(mismatch)),
        ];
        for (i, (challenge, answer, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                Expect::of(&challenge).check(&answer).err(),
                expected,
                "case {i}"
            );
        }
    }
}
