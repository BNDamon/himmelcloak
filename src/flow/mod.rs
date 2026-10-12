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
//! The resumable, caller-driven auth state machine.
//!
//! `Challenge`, `Answer`, `AuthStep`, and `AuthFlow` are the public contract every factor plugs
//! into. A flow is single-use: it ends on completion, cancellation, or expiry.
pub mod classify;
pub mod driver;
pub(crate) mod fetch;

use std::time::{Duration, Instant};

use crate::authenticator::{WebAuthnAssertion, WebAuthnChallenge};
use crate::error::{Error, Result};
use zeroize::Zeroize;

/// Client-side limit on one whole login, matching Keycloak's default login timeout. Keycloak still
/// enforces its own per-action timeouts.
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Returned by both `initiate_auth_flow` and `continue_auth_flow`.
#[non_exhaustive]
pub enum AuthStep {
    Challenge(Challenge),
    Complete(Tokens),
    /// Keycloak ended the login with an error page; `reason` is its message for the user.
    Failed {
        reason: String,
    },
}

/// A typed factor prompt handed to the caller (e.g. a PAM conversation).
#[non_exhaustive]
pub enum Challenge {
    /// Asked when `Start::login_hint` is absent: on identity-first pages, and before `Password`
    /// on Keycloak's combined login page, whose form the flow posts once both are answered.
    Username,
    Password,
    /// Keycloak's built-in TOTP/HOTP page, listing the user's devices when more than one exists.
    /// SMS and email codes come from add-on authenticators; they are Priority 2 and not modeled yet.
    OneTimeCode {
        devices: Vec<OtpDevice>,
    },
    RecoveryCode {
        index_hint: Option<u32>,
    },
    WebAuthn(WebAuthnChallenge),
    ChooseMethod {
        methods: Vec<AuthMethod>,
    },
    RequiredAction(RequiredAction),
    /// An information page the user must acknowledge before the login continues.
    Info {
        message: String,
    },
}

/// How the caller should collect the answer to a `Challenge`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Input {
    Hidden,
    Visible,
    /// Show the message only; the answer needs no typed input.
    None,
    /// A required-action form; each of `RequiredAction::fields` says whether it is secret.
    Form,
}

impl Challenge {
    /// Echo hint for the prompt, following the PAM message styles in the design.
    pub fn input(&self) -> Input {
        match self {
            Self::Password | Self::OneTimeCode { .. } | Self::RecoveryCode { .. } => Input::Hidden,
            Self::Username | Self::ChooseMethod { .. } => Input::Visible,
            Self::RequiredAction(_) => Input::Form,
            Self::WebAuthn(_) | Self::Info { .. } => Input::None,
        }
    }
}

/// One OTP device the user can pick on Keycloak's code page.
#[non_exhaustive]
pub struct OtpDevice {
    /// Value posted back as `selectedCredentialId`.
    pub id: String,
    pub label: String,
}

impl OtpDevice {
    pub fn new(id: String, label: String) -> Self {
        Self { id, label }
    }
}

/// One sign-in method offered on Keycloak's method-selection page.
#[non_exhaustive]
pub struct AuthMethod {
    /// Value posted back as `authenticationExecution`.
    pub id: String,
    pub label: String,
}

impl AuthMethod {
    pub fn new(id: String, label: String) -> Self {
        Self { id, label }
    }
}

/// The caller's response to a `Challenge`. Secret values are wiped when it is dropped.
#[non_exhaustive]
pub enum Answer {
    Username(String),
    Password(String),
    /// `device` is the chosen `OtpDevice::id`, or `None` when only one device exists.
    OneTimeCode {
        code: String,
        device: Option<String>,
    },
    RecoveryCode(String),
    WebAuthn(WebAuthnAssertion),
    /// The chosen `AuthMethod::id`.
    ChooseMethod(String),
    RequiredAction(RequiredActionAnswer),
    Acknowledge,
}

impl Drop for Answer {
    fn drop(&mut self) {
        match self {
            Self::Password(secret) | Self::RecoveryCode(secret) => secret.zeroize(),
            Self::OneTimeCode { code, .. } => code.zeroize(),
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowState {
    Active,
    Cancelled,
    Expired,
    Finished,
}

/// Resumable continue-state (cookie jar, action_url, execution, session_code, tab_id,
/// pkce_verifier, ...). Saving and resuming a flow across processes is Priority 2.
pub struct AuthFlow {
    /// Cookies for this login attempt only; wiped when the flow ends or is dropped.
    pub(crate) jar: fetch::CookieJar,
    deadline: Instant,
    state: FlowState,
}

impl AuthFlow {
    pub(crate) fn new(time_limit: Duration) -> Self {
        Self {
            jar: fetch::CookieJar::default(),
            deadline: Instant::now() + time_limit,
            state: FlowState::Active,
        }
    }

    /// Abandon the login and wipe its session cookies. Later answers are rejected.
    pub fn cancel(&mut self) {
        self.expire_if_due();
        self.end(FlowState::Cancelled);
    }

    /// True while the login can still take an answer. A login past its time limit ends here.
    pub fn is_active(&mut self) -> bool {
        self.expire_if_due();
        self.state == FlowState::Active
    }

    /// Gate every step: a cancelled, expired, or finished login never reaches Keycloak again.
    pub(crate) fn ensure_active(&mut self) -> Result<()> {
        self.expire_if_due();
        match self.state {
            FlowState::Active => Ok(()),
            FlowState::Cancelled => Err(Error::Cancelled),
            FlowState::Expired => Err(Error::Expired),
            FlowState::Finished => Err(Error::Protocol("login flow already finished")),
        }
    }

    /// Mark a successful login done; a login that ran past its deadline reports `Expired` instead.
    pub(crate) fn finish(&mut self) -> Result<()> {
        self.ensure_active()?;
        self.end(FlowState::Finished);
        Ok(())
    }

    fn expire_if_due(&mut self) {
        if self.state == FlowState::Active && Instant::now() >= self.deadline {
            self.end(FlowState::Expired);
        }
    }

    fn end(&mut self, state: FlowState) {
        if self.state == FlowState::Active {
            self.state = state;
        }
        self.jar = fetch::CookieJar::default();
    }
}

/// A Keycloak required action: UPDATE_PASSWORD, UPDATE_PROFILE, or TERMS_AND_CONDITIONS. Actions
/// that need browser-only setup, such as CONFIGURE_TOTP, end the login with `UnsupportedFactor`.
#[non_exhaustive]
pub struct RequiredAction {
    pub kind: String,
    /// Text to show before the fields, such as the terms the user is accepting.
    pub message: Option<String>,
    /// The form's inputs in page order; empty when the page only needs confirming (terms).
    pub fields: Vec<Field>,
}

impl RequiredAction {
    pub fn new(kind: String, message: Option<String>, fields: Vec<Field>) -> Self {
        Self {
            kind,
            message,
            fields,
        }
    }
}

/// One input on a required-action form.
#[non_exhaustive]
pub struct Field {
    /// Form field name posted back to Keycloak (e.g. `password-new`, `totp`, `userLabel`).
    pub name: String,
    pub label: String,
    /// Hide what the user types (a password or code).
    pub secret: bool,
}

impl Field {
    pub fn new(name: String, label: String, secret: bool) -> Self {
        Self {
            name,
            label,
            secret,
        }
    }
}

/// The caller's response to a required action: one `(Field::name, value)` pair per field.
#[non_exhaustive]
pub struct RequiredActionAnswer {
    pub values: Vec<(String, String)>,
}

impl RequiredActionAnswer {
    pub fn new(values: Vec<(String, String)>) -> Self {
        Self { values }
    }
}

impl Drop for RequiredActionAnswer {
    fn drop(&mut self) {
        for (_, value) in &mut self.values {
            value.zeroize();
        }
    }
}

/// OIDC tokens and the identity verified during the login session.
#[derive(Default)]
#[non_exhaustive]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub(crate) verified_subject: Option<String>,
    pub(crate) verified_issuer: Option<String>,
    pub(crate) verified_client_id: Option<String>,
    // Private copy binds the caller-visible refresh token to its verified
    // session. A caller cannot substitute another session's refresh token.
    pub(crate) verified_refresh_token: Option<String>,
}

impl Drop for Tokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
        if let Some(token) = &mut self.id_token {
            token.zeroize();
        }
        self.verified_subject.zeroize();
        self.verified_issuer.zeroize();
        self.verified_client_id.zeroize();
        self.verified_refresh_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::driver;

    fn password() -> Answer {
        Answer::Password("correct-horse-battery-staple".to_owned())
    }

    fn flow_with_cookie(time_limit: Duration) -> AuthFlow {
        let mut flow = AuthFlow::new(time_limit);
        let keycloak = url::Url::parse("https://keycloak.test/realms/test").unwrap();
        flow.jar.seed_session_cookie(&keycloak);
        assert!(!flow.jar.is_empty());
        flow
    }

    #[test]
    fn active_flow_reaches_the_driver() {
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT);
        assert!(flow.is_active());
        assert!(matches!(
            driver::advance(&mut flow, password()),
            Err(Error::NotImplemented)
        ));
    }

    #[test]
    fn cancelled_flow_rejects_every_later_step() {
        let mut flow = flow_with_cookie(DEFAULT_LOGIN_TIMEOUT);
        flow.cancel();
        assert!(!flow.is_active());
        assert!(flow.jar.is_empty());
        assert!(matches!(
            driver::advance(&mut flow, password()),
            Err(Error::Cancelled)
        ));
        assert!(matches!(driver::step(&mut flow), Err(Error::Cancelled)));
    }

    #[test]
    fn flow_past_its_time_limit_expires() {
        let mut flow = flow_with_cookie(Duration::ZERO);
        assert!(!flow.is_active());
        assert!(matches!(
            driver::advance(&mut flow, password()),
            Err(Error::Expired)
        ));
        assert!(flow.jar.is_empty());
        assert!(matches!(driver::step(&mut flow), Err(Error::Expired)));
    }

    #[test]
    fn checking_an_expired_flow_wipes_its_cookies() {
        let mut flow = flow_with_cookie(Duration::ZERO);
        assert!(!flow.is_active());
        assert!(flow.jar.is_empty());
    }

    #[test]
    fn cancel_after_expiry_keeps_the_expired_outcome() {
        let mut flow = flow_with_cookie(Duration::ZERO);
        flow.cancel();
        assert!(flow.jar.is_empty());
        assert!(matches!(flow.ensure_active(), Err(Error::Expired)));
    }

    #[test]
    fn expired_flow_cannot_finish() {
        let mut flow = flow_with_cookie(Duration::ZERO);
        assert!(matches!(flow.finish(), Err(Error::Expired)));
        assert!(flow.jar.is_empty());
        assert!(matches!(flow.ensure_active(), Err(Error::Expired)));
    }

    #[test]
    fn finished_flow_cannot_be_replayed() {
        let mut flow = flow_with_cookie(DEFAULT_LOGIN_TIMEOUT);
        flow.finish().unwrap();
        assert!(flow.jar.is_empty());
        flow.cancel();
        assert!(!flow.is_active());
        assert!(matches!(
            driver::advance(&mut flow, Answer::Acknowledge),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn input_hints_follow_the_pam_message_styles() {
        let update_password = RequiredAction::new(
            "UPDATE_PASSWORD".to_owned(),
            None,
            vec![
                Field::new("password-new".to_owned(), "New password".to_owned(), true),
                Field::new("password-confirm".to_owned(), "Confirm".to_owned(), true),
            ],
        );
        let terms = RequiredAction::new(
            "TERMS_AND_CONDITIONS".to_owned(),
            Some("Terms of use".to_owned()),
            vec![],
        );
        assert_eq!(Challenge::Password.input(), Input::Hidden);
        assert_eq!(
            Challenge::OneTimeCode { devices: vec![] }.input(),
            Input::Hidden
        );
        assert_eq!(
            Challenge::RecoveryCode {
                index_hint: Some(3)
            }
            .input(),
            Input::Hidden
        );
        assert_eq!(Challenge::Username.input(), Input::Visible);
        assert_eq!(
            Challenge::ChooseMethod { methods: vec![] }.input(),
            Input::Visible
        );
        assert_eq!(
            Challenge::RequiredAction(update_password).input(),
            Input::Form
        );
        assert_eq!(Challenge::RequiredAction(terms).input(), Input::Form);
        assert_eq!(
            Challenge::Info {
                message: "Check your email".to_owned()
            }
            .input(),
            Input::None
        );
    }
}
