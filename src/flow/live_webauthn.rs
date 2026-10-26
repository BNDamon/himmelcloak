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
//! Test-only bridge to stock Keycloak's WebAuthn page; no production page parser.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use html5gum::{DefaultEmitter, Token, Tokenizer};
use url::Url;

use crate::authenticator::software::SoftwareAuthenticator;
use crate::authenticator::{
    CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
};
use crate::client::{PublicClientApplication, Start};
use crate::flow::{driver, fetch, form, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::CurlTransport;

fn fixture_page(page: &fetch::Page) -> (Url, String) {
    let html = std::str::from_utf8(&page.body).unwrap();
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true);
    let mut action = None;
    let mut offered = false;
    let authenticator = SoftwareAuthenticator::realm_fixture();
    let credential_id = URL_SAFE_NO_PAD.encode(authenticator.credential_id());
    for token in Tokenizer::new_with_emitter(html, emitter) {
        let Ok(Token::StartTag(tag)) = token else {
            continue;
        };
        let attr = |name: &[u8]| {
            tag.attributes
                .iter()
                .find(|(key, _)| key.as_ref() == name)
                .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        };
        if tag.name.as_ref() == b"form" && attr(b"id").as_deref() == Some("webauth") {
            assert_eq!(attr(b"method").as_deref(), Some("post"));
            assert!(action.is_none());
            action = Some(page.url.join(&attr(b"action").unwrap()).unwrap());
        }
        if attr(b"name").as_deref() == Some("authn_use_chk") {
            offered |= attr(b"value").as_deref() == Some(credential_id.as_str());
        }
    }
    assert!(offered, "Keycloak must offer the preloaded credential");
    let action = action.expect("Keycloak WebAuthn form");
    assert_eq!(action.origin(), page.url.origin());
    assert_eq!(action.scheme(), "https");
    assert!(action.path().ends_with("/login-actions/authenticate"));
    // Stock template renders these as JavaScript object properties with JSON string values.
    let property = |name: &str| {
        let tail = html
            .split_once(&format!("{name} :"))
            .expect("WebAuthn option")
            .1
            .trim_start();
        serde_json::Deserializer::from_str(tail)
            .into_iter::<String>()
            .next()
            .unwrap()
            .unwrap()
    };
    assert_eq!(property("rpId"), "keycloak.test");
    assert_eq!(property("userVerification"), "discouraged");
    let challenge = property("challenge");
    assert!(!URL_SAFE_NO_PAD.decode(&challenge).unwrap().is_empty());
    (action, challenge)
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn seeded_webauthn_credential_is_verified_and_tampering_is_rejected() {
    let mut config = super::live::config();
    config.client_id = "himmelcloak-webauthn".into();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();
    let authenticator = SoftwareAuthenticator::realm_fixture();

    // Reuse the same credential so Keycloak also verifies a strictly increasing counter.
    for tamper in [false, true, false] {
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        let url = app.authorization_url(&Start::default(), &mut flow).unwrap();
        let fetch::Fetched::Page(page) = fetch::get(&transport, &mut flow.jar, url).await.unwrap()
        else {
            panic!("expected a login form");
        };
        let (_, login) = form::extract(&page).unwrap();
        let fetch::Fetched::Page(page) = login
            .submit(
                &transport,
                &mut flow.jar,
                &[
                    ("username", "passkey-test"),
                    ("password", "correct-horse-battery-staple"),
                ],
            )
            .await
            .unwrap()
        else {
            panic!("password alone must not complete login")
        };
        let (action, challenge) = fixture_page(&page);
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": challenge,
            "origin": page.url.origin().ascii_serialization(), "crossOrigin": false,
        }))
        .unwrap();
        let request = WebAuthnGetRequest {
            rp_id: "keycloak.test".into(),
            client_data_hash: crate::crypto::sha256(&client_data).unwrap(),
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Discouraged,
        };
        let mut assertion = authenticator.get_assertion(&request).unwrap();
        if tamper {
            *assertion.signature.last_mut().unwrap() ^= 0xFF;
        }
        let client_data = URL_SAFE_NO_PAD.encode(client_data);
        let data = URL_SAFE_NO_PAD.encode(assertion.authenticator_data);
        let signature = URL_SAFE_NO_PAD.encode(assertion.signature);
        let credential = URL_SAFE_NO_PAD.encode(assertion.credential_id);
        let reply = fetch::post_form(
            &transport,
            &mut flow.jar,
            action,
            &[
                ("clientDataJSON", &client_data),
                ("authenticatorData", &data),
                ("signature", &signature),
                ("credentialId", &credential),
                ("userHandle", ""),
            ],
        )
        .await
        .unwrap();
        if tamper {
            let fetch::Fetched::Page(page) = reply else {
                panic!("tampering must not issue a code");
            };
            assert!(
                page.status < 500,
                "server failure is not a credential rejection"
            );
        } else {
            let fetch::Fetched::Redirect(redirect) = reply else {
                panic!("valid assertion must issue a code")
            };
            let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
                .unwrap()
                .unwrap();
            let tokens = app.exchange_code(callback, &mut flow).await.unwrap();
            assert!(tokens.id_token.is_some());
            let user = app.userinfo(&tokens).await.unwrap();
            assert_eq!(user["preferred_username"], "passkey-test");
        }
    }
}
