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

use crate::error::{Error, Result};
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
    fn for_page(&self, kind: &PageKind) -> Option<&dyn PageFactor> {
        // The one-time-code handler registers here when its slice lands.
        match kind {
            PageKind::UsernamePassword { .. } => Some(&PasswordFactor),
            _ => None,
        }
    }
}

/// Keycloak's combined username-and-password page, `login.ftl` (charter Table 2, §2.3 item 3a).
/// It asks the username, unless `Start::login_hint` already filled it in, then the password,
/// and posts both. The page's other fields, such as `credentialId`, keep the page's own values.
pub(crate) struct PasswordFactor;

impl PageFactor for PasswordFactor {
    fn challenges(&self, kind: &PageKind, login_hint: Option<&str>) -> Result<Vec<Challenge>> {
        match kind {
            PageKind::UsernamePassword { .. } if login_hint.is_some() => {
                Ok(vec![Challenge::Password])
            }
            PageKind::UsernamePassword { .. } => Ok(vec![Challenge::Username, Challenge::Password]),
            _ => Err(Error::UnsupportedFactor),
        }
    }

    fn fields(
        &self,
        _kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>> {
        answers
            .iter()
            .map(|answer| match answer {
                Answer::Username(name) => Ok(("username".to_owned(), Zeroizing::new(name.clone()))),
                Answer::Password(password) => {
                    Ok(("password".to_owned(), Zeroizing::new(password.clone())))
                }
                // The driver checks each answer against its challenge, so this is a caller bug.
                _ => Err(Error::Protocol(
                    "answer does not belong to the password page",
                )),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Builtin, Factors, PageFactor, PasswordFactor};
    use crate::error::Error;
    use crate::flow::classify::PageKind;
    use crate::flow::{Answer, Challenge};

    fn login_page() -> PageKind {
        PageKind::UsernamePassword { error: None }
    }

    #[test]
    fn builtin_handles_the_login_page_and_nothing_else_yet() {
        assert!(Builtin.for_page(&login_page()).is_some());
        let code_page = PageKind::OneTimeCode {
            devices: Vec::new(),
        };
        assert!(Builtin.for_page(&code_page).is_none());
        assert!(Builtin.for_page(&PageKind::Unknown).is_none());
    }

    #[test]
    fn the_login_page_asks_the_username_unless_the_hint_filled_it_in() {
        let asked = PasswordFactor.challenges(&login_page(), None).unwrap();
        assert!(matches!(
            asked.as_slice(),
            [Challenge::Username, Challenge::Password]
        ));
        let asked = PasswordFactor
            .challenges(&login_page(), Some("alice"))
            .unwrap();
        assert!(matches!(asked.as_slice(), [Challenge::Password]));
        assert_eq!(
            PasswordFactor.challenges(&PageKind::Unknown, None).err(),
            Some(Error::UnsupportedFactor)
        );
    }

    #[test]
    fn answers_become_the_login_pages_fields() {
        let answers = [
            Answer::Username("alice".to_owned()),
            Answer::Password("synthetic-password".to_owned()),
        ];
        let fields = PasswordFactor.fields(&login_page(), &answers).unwrap();
        let fields: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("username", "alice"), ("password", "synthetic-password")]
        );
        // With a login hint only the password is asked, so only it is posted.
        let fields = PasswordFactor
            .fields(&login_page(), &[Answer::Password("p".to_owned())])
            .unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "password");
        assert_eq!(
            PasswordFactor
                .fields(&login_page(), &[Answer::Acknowledge])
                .err(),
            Some(Error::Protocol(
                "answer does not belong to the password page"
            ))
        );
    }
}
