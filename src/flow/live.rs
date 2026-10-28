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
//! Live Keycloak scenarios for flow pieces the public API does not expose on their own.
//!
//! Each feature needs a successful and a rejected scenario against stock Keycloak (charter
//! section 2.7.7). A whole login through the public API is tested in `tests/live_keycloak.rs`;
//! these check the pieces underneath it (form submission, the callback, and the code exchange),
//! so they run inside the crate. The live suite runs both with
//! `cargo test --lib --test live_keycloak -- --ignored`, and they need `KEYCLOAK_URL` and
//! `KEYCLOAK_CA`.
use std::path::PathBuf;
use std::time::Duration;

use crate::client::{PublicClientApplication, Start};
use crate::config::Config;
use crate::error::Error;
use crate::flow::classify::PageKind;
use crate::flow::fetch::{self, Fetched, Redirect};
use crate::flow::form::{extract, Form};
use crate::flow::{driver, AuthFlow, AuthStep, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::CurlTransport;

const PASSWORD: &str = "correct-horse-battery-staple";
/// The test realm's client with direct grants disabled, so these scenarios prove the
/// browser-free flow works without the password grant (charter section 2.7.3).
const BROWSER_ONLY_CLIENT: &str = "himmelcloak-browser-only";

fn trace(message: &str) {
    if std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some() {
        eprintln!("[himmelcloak client] {message}");
    }
}

pub(super) fn config() -> Config {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let mut config = Config::new(&server, "himmelcloak-test", BROWSER_ONLY_CLIENT).unwrap();
    config.ca_bundle = Some(PathBuf::from(ca));
    config
}

/// Start a login with `flow` and return the login page's form.
async fn login_form(
    app: &PublicClientApplication,
    transport: &CurlTransport,
    flow: &mut AuthFlow,
) -> Form {
    let url = app.authorization_url(&Start::default(), flow).unwrap();
    let Fetched::Page(page) = fetch::get(transport, &mut flow.jar, url).await.unwrap() else {
        panic!("expected Keycloak's login page");
    };
    let (kind, form) = extract(&page).unwrap();
    assert!(matches!(kind, PageKind::UsernamePassword { .. }));
    form
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_password_form_reaches_the_callback_and_a_wrong_password_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    trace("submit alice's login form with the correct password");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback");
    assert!(!callback.code.is_empty());
    trace("Keycloak redirected to the callback with a code for this login's state");

    trace("submit alice's login form with a wrong password");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", "wrong-password")],
        )
        .await
        .unwrap();
    let Fetched::Page(page) = fetched else {
        panic!("a wrong password must not redirect");
    };
    let (kind, _) = extract(&page).unwrap();
    assert!(matches!(kind, PageKind::UsernamePassword { .. }));
    trace("Keycloak rejected the wrong password and showed the login page again");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_code_exchange_returns_verified_tokens_and_a_wrong_code_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    trace("log alice in and exchange the callback's code");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback");
    let tokens = app.exchange_code(callback, &mut flow).await.unwrap();
    assert!(tokens.id_token.is_some());
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    assert_eq!(
        tokens.verified_issuer.as_deref(),
        Some(config.issuer().unwrap().as_str())
    );
    assert!(!flow.is_active());
    trace("Keycloak issued tokens that passed the ID token checks");

    trace("exchange a code Keycloak never issued");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let wrong = driver::Callback {
        code: "not-a-code-keycloak-issued".to_owned(),
    };
    assert_eq!(
        app.exchange_code(wrong, &mut flow).await.err(),
        Some(Error::AuthenticationRejected)
    );
    trace("Keycloak rejected the wrong code");
}

/// Log alice in with `flow` and return Keycloak's redirect to the callback.
async fn log_in(
    app: &PublicClientApplication,
    transport: &CurlTransport,
    flow: &mut AuthFlow,
) -> Redirect {
    let form = login_form(app, transport, flow).await;
    let fetched = form
        .submit(
            transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    redirect
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_login_completes_without_direct_grants_and_a_replayed_code_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    // The password grant must really be off for this client, or the scenario proves nothing.
    #[cfg(feature = "password")]
    {
        trace("confirm the password grant is refused for the browser-only client");
        assert_eq!(
            app.acquire_token_by_password("alice", PASSWORD, None)
                .await
                .err(),
            Some(Error::InvalidConfiguration(
                "Keycloak rejected the client or requested grant"
            ))
        );
    }

    trace("log alice in through the authorization-code flow");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let redirect = log_in(&app, &transport, &mut flow).await;
    // Replay the code exactly as this login would send it, so only the reuse can fail.
    let mut replay = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    replay.pkce_verifier = flow.pkce_verifier.clone();
    replay.nonce = flow.nonce.clone();
    let code = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback")
        .code
        .clone();
    let Some(AuthStep::Complete(tokens)) = app
        .complete_at_callback(&redirect, &mut flow)
        .await
        .unwrap()
    else {
        panic!("the callback must complete the login");
    };
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    assert_eq!(
        tokens.verified_issuer.as_deref(),
        Some(config.issuer().unwrap().as_str())
    );
    assert!(!flow.is_active());
    trace("the login completed with verified tokens");

    trace("redeem the same code again with the login's verifier and nonce");
    assert_eq!(
        app.exchange_code(driver::Callback { code }, &mut replay)
            .await
            .err(),
        Some(Error::AuthenticationRejected)
    );
    // Reuse also revokes what the code first issued (RFC 6749 section 4.1.2).
    assert_eq!(
        app.refresh_tokens(&tokens).await.err(),
        Some(Error::AuthenticationRejected)
    );
    trace("Keycloak refused the reused code and revoked its session");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_code_held_past_its_lifespan_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    trace("log alice in and hold the code past the test realm's 10 s code lifespan");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let redirect = log_in(&app, &transport, &mut flow).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_eq!(
        app.complete_at_callback(&redirect, &mut flow).await.err(),
        Some(Error::AuthenticationRejected)
    );
    assert!(!flow.is_active());
    trace("Keycloak refused the stale code");
}
