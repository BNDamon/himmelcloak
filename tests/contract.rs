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

//! A stub factor handler written against the public contract only, the way PAM and the CLI will.
use himmelcloak::authenticator::{
    CredentialDescriptor, UserVerification, WebAuthnAssertion, WebAuthnChallenge,
};
use himmelcloak::flow::{Field, RequiredAction, RequiredActionAnswer};
use himmelcloak::{Answer, AuthMethod, Challenge, Input, OtpDevice};

/// Answers every challenge from canned values, or `None` when it cannot.
struct StubHandler;

impl StubHandler {
    fn answer(&self, challenge: &Challenge) -> Option<Answer> {
        let answer = match challenge {
            Challenge::Username => Answer::Username("alice".to_owned()),
            Challenge::Password => Answer::Password("correct-horse-battery-staple".to_owned()),
            Challenge::OneTimeCode { devices } => Answer::OneTimeCode {
                code: "123456".to_owned(),
                device: devices.first().map(|device| device.id.clone()),
            },
            Challenge::RecoveryCode { .. } => Answer::RecoveryCode("1234-5678".to_owned()),
            Challenge::WebAuthn(request) => Answer::WebAuthn(WebAuthnAssertion {
                authenticator_data: vec![0; 37],
                signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
                credential_id: request.allow_credentials.first()?.id.clone(),
                user_handle: None,
            }),
            Challenge::ChooseMethod { methods } => {
                Answer::ChooseMethod(methods.first()?.id.clone())
            }
            Challenge::RequiredAction(action) => Answer::RequiredAction(RequiredActionAnswer::new(
                action
                    .fields
                    .iter()
                    .map(|field| (field.name.clone(), self.fill(field)))
                    .collect(),
            )),
            Challenge::Info { .. } => Answer::Acknowledge,
            _ => return None,
        };
        Some(answer)
    }

    /// A real caller prompts per field, hiding input when the field says so.
    fn fill(&self, field: &Field) -> String {
        if field.secret {
            "hidden-entry".to_owned()
        } else {
            format!("shown-{}", field.name)
        }
    }
}

fn update_profile() -> Challenge {
    Challenge::RequiredAction(RequiredAction::new(
        "UPDATE_PROFILE".to_owned(),
        None,
        vec![
            Field::new("email".to_owned(), "Email".to_owned(), false),
            Field::new("firstName".to_owned(), "First name".to_owned(), false),
        ],
    ))
}

fn update_password() -> Challenge {
    Challenge::RequiredAction(RequiredAction::new(
        "UPDATE_PASSWORD".to_owned(),
        None,
        vec![
            Field::new("password-new".to_owned(), "New password".to_owned(), true),
            Field::new("password-confirm".to_owned(), "Confirm".to_owned(), true),
        ],
    ))
}

fn terms() -> Challenge {
    Challenge::RequiredAction(RequiredAction::new(
        "TERMS_AND_CONDITIONS".to_owned(),
        Some("You agree to the acceptable use policy.".to_owned()),
        vec![],
    ))
}

fn values(challenge: &Challenge) -> Vec<(String, String)> {
    let reply = StubHandler.answer(challenge);
    let Some(Answer::RequiredAction(answer)) = reply.as_ref() else {
        panic!("expected a required-action answer");
    };
    answer.values.clone()
}

fn webauthn_challenge() -> Challenge {
    Challenge::WebAuthn(WebAuthnChallenge {
        rp_id: "keycloak.test".to_owned(),
        challenge: vec![7; 32],
        allow_credentials: vec![CredentialDescriptor { id: vec![1, 2, 3] }],
        user_verification: UserVerification::Preferred,
        origin: "https://keycloak.test".to_owned(),
    })
}

#[test]
fn stub_handler_answers_each_prompt_kind() {
    let handler = StubHandler;
    let devices = vec![OtpDevice::new(
        "phone-credential-id".to_owned(),
        "Phone".to_owned(),
    )];
    let methods = vec![AuthMethod::new(
        "otp-execution-id".to_owned(),
        "Authenticator app".to_owned(),
    )];

    assert!(matches!(
        handler.answer(&Challenge::Username).as_ref(),
        Some(Answer::Username(name)) if name == "alice"
    ));
    assert!(matches!(
        handler.answer(&Challenge::Password).as_ref(),
        Some(Answer::Password(_))
    ));
    assert!(matches!(
        handler.answer(&Challenge::OneTimeCode { devices }).as_ref(),
        Some(Answer::OneTimeCode { device: Some(id), .. }) if id == "phone-credential-id"
    ));
    assert!(matches!(
        handler.answer(&Challenge::ChooseMethod { methods }).as_ref(),
        Some(Answer::ChooseMethod(id)) if id == "otp-execution-id"
    ));
    assert!(handler
        .answer(&Challenge::ChooseMethod { methods: vec![] })
        .is_none());
    assert!(matches!(
        handler.answer(&webauthn_challenge()).as_ref(),
        Some(Answer::WebAuthn(assertion)) if assertion.credential_id == [1, 2, 3]
    ));
    assert!(matches!(
        handler
            .answer(&Challenge::RecoveryCode {
                index_hint: Some(2)
            })
            .as_ref(),
        Some(Answer::RecoveryCode(_))
    ));
    assert!(matches!(
        handler
            .answer(&Challenge::Info {
                message: "Check your email".to_owned()
            })
            .as_ref(),
        Some(Answer::Acknowledge)
    ));
}

#[test]
fn required_action_forms_hide_only_secret_fields() {
    assert_eq!(update_password().input(), Input::Form);
    assert_eq!(
        values(&update_password()),
        [
            ("password-new".to_owned(), "hidden-entry".to_owned()),
            ("password-confirm".to_owned(), "hidden-entry".to_owned()),
        ]
    );
    assert_eq!(
        values(&update_profile()),
        [
            ("email".to_owned(), "shown-email".to_owned()),
            ("firstName".to_owned(), "shown-firstName".to_owned()),
        ]
    );
}

#[test]
fn terms_show_their_text_and_need_no_fields() {
    let challenge = terms();
    let Challenge::RequiredAction(action) = &challenge else {
        panic!("expected a required action");
    };
    assert_eq!(
        action.message.as_deref(),
        Some("You agree to the acceptable use policy.")
    );
    assert!(values(&challenge).is_empty());
}

#[test]
fn every_prompt_kind_has_an_input_hint() {
    let prompts = [
        (Challenge::Username, Input::Visible),
        (Challenge::Password, Input::Hidden),
        (Challenge::OneTimeCode { devices: vec![] }, Input::Hidden),
        (Challenge::RecoveryCode { index_hint: None }, Input::Hidden),
        (Challenge::ChooseMethod { methods: vec![] }, Input::Visible),
        (webauthn_challenge(), Input::None),
        (
            Challenge::Info {
                message: "Check your email".to_owned(),
            },
            Input::None,
        ),
    ];
    for (challenge, input) in prompts {
        assert_eq!(challenge.input(), input);
    }
}
