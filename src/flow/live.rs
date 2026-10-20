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
//! Live Keycloak scenarios for flow pieces the public API cannot reach yet.
//!
//! Each feature needs a successful and a rejected scenario against stock Keycloak (charter
//! section 2.7.7). Until `initiate_auth_flow` drives a whole login, these run inside the crate,
//! and the live suite runs them with `cargo test --lib --test live_keycloak -- --ignored`. They
//! need `KEYCLOAK_URL` and `KEYCLOAK_CA`, like `tests/live_keycloak.rs`.
use std::path::PathBuf;

use crate::client::{PublicClientApplication, Start};
use crate::config::Config;
use crate::flow::classify::PageKind;
use crate::flow::fetch::{self, Fetched};
use crate::flow::form::{extract, Form};
use crate::flow::{driver, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
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

fn config() -> Config {
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
    assert!(matches!(kind, PageKind::UsernamePassword));
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

    // The password grant must really be off for this client, or the scenario proves nothing.
    #[cfg(feature = "password")]
    {
        trace("confirm the password grant is refused for the browser-only client");
        assert!(app
            .acquire_token_by_password("alice", PASSWORD, None)
            .await
            .is_err());
    }

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
    assert!(matches!(kind, PageKind::UsernamePassword));
    trace("Keycloak rejected the wrong password and showed the login page again");
}
