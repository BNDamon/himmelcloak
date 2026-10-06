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

use std::path::PathBuf;

use himmelcloak::config::Config;
use himmelcloak::error::Error;
use himmelcloak::PublicClientApplication;

fn trace(message: &str) {
    if std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some() {
        eprintln!("[himmelcloak client] {message}");
    }
}

fn config() -> Config {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let mut config = Config::new(&server, "himmelcloak-test", "himmelcloak-test-client").unwrap();
    config.ca_bundle = Some(PathBuf::from(ca));
    config
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
#[cfg(feature = "password")]
async fn direct_grant_lifecycle() {
    trace("discover Keycloak OIDC metadata and signing keys over HTTPS");
    let app = PublicClientApplication::with_config(config())
        .await
        .unwrap();
    trace("send alice with an incorrect password");
    assert!(matches!(
        app.acquire_token_by_password("alice", "wrong-password", None)
            .await,
        Err(Error::AuthenticationRejected)
    ));
    trace("Keycloak rejected the incorrect password");

    trace("send alice with the correct password");
    let mut tokens = app
        .acquire_token_by_password("alice", "correct-horse-battery-staple", None)
        .await
        .unwrap();
    assert!(tokens.id_token.is_some());
    trace("Keycloak issued tokens; himmelcloak verified the signed ID token");
    let user = app.userinfo(&tokens).await.unwrap();
    assert_eq!(user["preferred_username"], "alice");
    trace("userinfo returned alice with the same verified subject");

    let mut forged = tokens.id_token.as_ref().unwrap().as_bytes().to_vec();
    let signature_start = forged.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    forged[signature_start] = if forged[signature_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let original = tokens.id_token.replace(String::from_utf8(forged).unwrap());
    assert!(matches!(
        app.userinfo(&tokens).await,
        Err(Error::TokenValidation(_))
    ));
    tokens.id_token = original;
    trace("himmelcloak rejected a tampered ID-token signature");

    trace("refresh the Keycloak session");
    let refreshed = app.refresh_tokens(&tokens).await.unwrap();
    assert!(!refreshed.access_token.is_empty());
    trace("Keycloak accepted the refresh token and issued new tokens");
    let refreshed_user = app.userinfo(&refreshed).await.unwrap();
    assert_eq!(refreshed_user["preferred_username"], "alice");
    trace("refreshed session still resolves to alice");
    let revoked = refreshed.refresh_token.as_deref().expect("refresh token");
    app.revoke_token(revoked).await.unwrap();
    assert!(matches!(
        app.refresh_tokens(&refreshed).await,
        Err(Error::AuthenticationRejected)
    ));
    trace("Keycloak rejected the revoked refresh token");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn rejects_untrusted_keycloak_certificate() {
    let mut config = config();
    config.ca_bundle = None;
    assert!(matches!(
        PublicClientApplication::with_config(config).await,
        Err(Error::Transport(_))
    ));
    trace("himmelcloak rejected Keycloak without the trusted test CA");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn rejects_keycloak_host_name_mismatch() {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let mut url = url::Url::parse(&server).unwrap();
    // The compose service name reaches the same Keycloak but is not in the certificate's SANs.
    url.set_host(Some("keycloak")).unwrap();
    let mut config =
        Config::new(url.as_str(), "himmelcloak-test", "himmelcloak-test-client").unwrap();
    config.ca_bundle = Some(PathBuf::from(ca));
    assert!(matches!(
        PublicClientApplication::with_config(config).await,
        Err(Error::Transport(reason)) if reason.contains("SSL")
    ));
    trace("himmelcloak rejected Keycloak reached by a host name outside its certificate");
}
