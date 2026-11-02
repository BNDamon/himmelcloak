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
//! Pure translation of the real Himmelcloak Challenge API into planned PAM messages.
//! This layer never invokes a callback, collects a secret, or reports successful login.

use std::ffi::c_int;
use std::fmt;

use himmelcloak::Challenge;

/// Values from Linux-PAM's security/_pam_types.h.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageStyle {
    HiddenInput = 1,
    VisibleInput = 2,
    Error = 3,
    Information = 4,
}

impl MessageStyle {
    pub fn as_raw(self) -> c_int {
        self as c_int
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub style: MessageStyle,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    CollectInput,
    Acknowledge,
    WebAuthnAdapter,
    DisplayOnly,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConversationPlan {
    pub messages: Vec<Message>,
    pub next_action: NextAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationError {
    UnsupportedChallenge,
    EmptyMethodSelection,
    InteriorNul,
}

impl fmt::Display for TranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedChallenge => "Unsupported authentication challenge",
            Self::EmptyMethodSelection => "No authentication method was offered",
            Self::InteriorNul => "PAM message contains an interior NUL",
        })
    }
}
impl std::error::Error for TranslationError {}

fn message(style: MessageStyle, text: impl Into<String>) -> Message {
    Message {
        style,
        text: text.into(),
    }
}

fn checked(
    messages: Vec<Message>,
    next_action: NextAction,
) -> Result<ConversationPlan, TranslationError> {
    if messages.iter().any(|message| message.text.contains('\0')) {
        return Err(TranslationError::InteriorNul);
    }
    Ok(ConversationPlan {
        messages,
        next_action,
    })
}

pub fn plan(challenge: &Challenge) -> Result<ConversationPlan, TranslationError> {
    use MessageStyle::{HiddenInput, Information, VisibleInput};
    use NextAction::{Acknowledge, CollectInput, WebAuthnAdapter};

    let mut messages = Vec::new();
    let next_action = match challenge {
        Challenge::Username => {
            messages.push(message(VisibleInput, "Username: "));
            CollectInput
        }
        Challenge::Password => {
            messages.push(message(HiddenInput, "Password: "));
            CollectInput
        }
        Challenge::OneTimeCode { devices } => {
            if devices.len() > 1 {
                let mut selection = String::from("Choose an authenticator:\n");
                for (index, device) in devices.iter().enumerate() {
                    selection.push_str(&format!("{}. {}\n", index + 1, device.label));
                }
                selection.push_str("Selection: ");
                messages.push(message(VisibleInput, selection));
            }
            messages.push(message(HiddenInput, "One-time code: "));
            CollectInput
        }
        Challenge::RecoveryCode { index_hint } => {
            let prompt = match index_hint {
                Some(index) => format!("Recovery code {index}: "),
                None => "Recovery code: ".to_owned(),
            };
            messages.push(message(HiddenInput, prompt));
            CollectInput
        }
        Challenge::ChooseMethod { methods } => {
            if methods.is_empty() {
                return Err(TranslationError::EmptyMethodSelection);
            }
            let mut selection = String::from("Choose a sign-in method:\n");
            for (index, method) in methods.iter().enumerate() {
                selection.push_str(&format!("{}. {}\n", index + 1, method.label));
            }
            selection.push_str("Selection: ");
            messages.push(message(VisibleInput, selection));
            CollectInput
        }
        Challenge::RequiredAction(action) => {
            if let Some(text) = &action.message {
                messages.push(message(Information, text));
            }
            for field in &action.fields {
                let style = if field.secret {
                    HiddenInput
                } else {
                    VisibleInput
                };
                messages.push(message(style, format!("{}: ", field.label)));
            }
            if action.fields.is_empty() {
                Acknowledge
            } else {
                CollectInput
            }
        }
        Challenge::Info { message: text } => {
            messages.push(message(Information, text));
            Acknowledge
        }
        Challenge::WebAuthn(_) => {
            messages.push(message(
                Information,
                "Follow the instructions for your security key or authenticator.",
            ));
            WebAuthnAdapter
        }
        // The core enum is non-exhaustive: never silently accept a new factor.
        _ => return Err(TranslationError::UnsupportedChallenge),
    };
    checked(messages, next_action)
}

/// AuthStep::Failed is separate from Challenge and must be shown as a PAM error.
pub fn failure_plan(reason: &str) -> Result<ConversationPlan, TranslationError> {
    checked(
        vec![message(MessageStyle::Error, reason)],
        NextAction::DisplayOnly,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use himmelcloak::authenticator::{UserVerification, WebAuthnChallenge};
    use himmelcloak::flow::{Field, RequiredAction};
    use himmelcloak::{AuthMethod, OtpDevice};

    fn styles(challenge: Challenge) -> Vec<MessageStyle> {
        plan(&challenge)
            .unwrap()
            .messages
            .into_iter()
            .map(|m| m.style)
            .collect()
    }

    #[test]
    fn pam_style_values_match_linux_pam() {
        assert_eq!(MessageStyle::HiddenInput.as_raw(), 1);
        assert_eq!(MessageStyle::VisibleInput.as_raw(), 2);
        assert_eq!(MessageStyle::Error.as_raw(), 3);
        assert_eq!(MessageStyle::Information.as_raw(), 4);
    }

    #[test]
    fn username_is_visible_and_password_is_hidden() {
        assert_eq!(styles(Challenge::Username), [MessageStyle::VisibleInput]);
        assert_eq!(styles(Challenge::Password), [MessageStyle::HiddenInput]);
        assert_eq!(
            plan(&Challenge::Password).unwrap().next_action,
            NextAction::CollectInput
        );
    }

    #[test]
    fn otp_is_hidden_with_zero_or_one_device() {
        for devices in [vec![], vec![OtpDevice::new("id".into(), "Phone".into())]] {
            assert_eq!(
                styles(Challenge::OneTimeCode { devices }),
                [MessageStyle::HiddenInput]
            );
        }
    }

    #[test]
    fn otp_device_selection_is_visible_but_code_stays_hidden() {
        let challenge = Challenge::OneTimeCode {
            devices: vec![
                OtpDevice::new("a".into(), "Phone".into()),
                OtpDevice::new("b".into(), "Tablet".into()),
            ],
        };
        let result = plan(&challenge).unwrap();
        assert_eq!(
            result.messages.iter().map(|m| m.style).collect::<Vec<_>>(),
            [MessageStyle::VisibleInput, MessageStyle::HiddenInput]
        );
        assert!(result.messages[0].text.contains("1. Phone\n2. Tablet"));
    }

    #[test]
    fn recovery_codes_stay_hidden_with_and_without_an_index() {
        for index_hint in [None, Some(3)] {
            assert_eq!(
                styles(Challenge::RecoveryCode { index_hint }),
                [MessageStyle::HiddenInput]
            );
        }
        assert!(plan(&Challenge::RecoveryCode {
            index_hint: Some(3)
        })
        .unwrap()
        .messages[0]
            .text
            .contains('3'));
    }

    #[test]
    fn method_selection_is_visible() {
        let challenge = Challenge::ChooseMethod {
            methods: vec![AuthMethod::new("password".into(), "Password".into())],
        };
        assert_eq!(styles(challenge), [MessageStyle::VisibleInput]);
        assert_eq!(
            plan(&Challenge::ChooseMethod { methods: vec![] }),
            Err(TranslationError::EmptyMethodSelection)
        );
    }

    #[test]
    fn required_action_preserves_field_order_and_secrecy() {
        let action = RequiredAction::new(
            "UPDATE_PROFILE".into(),
            Some("Update your details".into()),
            vec![
                Field::new("name".into(), "Name".into(), false),
                Field::new("password-new".into(), "New password".into(), true),
            ],
        );
        let result = plan(&Challenge::RequiredAction(action)).unwrap();
        assert_eq!(
            result.messages.iter().map(|m| m.style).collect::<Vec<_>>(),
            [
                MessageStyle::Information,
                MessageStyle::VisibleInput,
                MessageStyle::HiddenInput
            ]
        );
        assert_eq!(result.messages[1].text, "Name: ");
        assert_eq!(result.messages[2].text, "New password: ");
        assert_eq!(result.next_action, NextAction::CollectInput);
    }

    #[test]
    fn required_action_without_fields_needs_explicit_acknowledgement() {
        let action =
            RequiredAction::new("TERMS_AND_CONDITIONS".into(), Some("Terms".into()), vec![]);
        let result = plan(&Challenge::RequiredAction(action)).unwrap();
        assert_eq!(result.messages[0].style, MessageStyle::Information);
        assert_eq!(result.next_action, NextAction::Acknowledge);
    }

    #[test]
    fn information_is_not_a_secret_or_visible_input_prompt() {
        let result = plan(&Challenge::Info {
            message: "Check your email".into(),
        })
        .unwrap();
        assert_eq!(result.messages[0].style, MessageStyle::Information);
        assert_eq!(result.next_action, NextAction::Acknowledge);
    }

    #[test]
    fn webauthn_requires_an_adapter_instead_of_a_typed_password() {
        let challenge = Challenge::WebAuthn(WebAuthnChallenge {
            rp_id: "keycloak.example".into(),
            challenge: vec![1, 2],
            allow_credentials: vec![],
            user_verification: UserVerification::Preferred,
            origin: "https://keycloak.example".into(),
        });
        let result = plan(&challenge).unwrap();
        assert_eq!(result.messages[0].style, MessageStyle::Information);
        assert_eq!(result.next_action, NextAction::WebAuthnAdapter);
    }

    #[test]
    fn failures_use_error_style_and_do_not_collect_input() {
        let result = failure_plan("Login expired").unwrap();
        assert_eq!(result.messages[0].style, MessageStyle::Error);
        assert_eq!(result.next_action, NextAction::DisplayOnly);
    }

    #[test]
    fn interior_nul_is_rejected_before_any_future_c_conversion() {
        assert_eq!(
            plan(&Challenge::Info {
                message: "bad\0message".into()
            }),
            Err(TranslationError::InteriorNul)
        );
        assert_eq!(
            failure_plan("bad\0error"),
            Err(TranslationError::InteriorNul)
        );
    }
}
