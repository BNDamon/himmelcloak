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
use std::future::Future;
use std::sync::{Arc, RwLock};

use serde_json::Value;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::flow::{driver, Answer, AuthFlow, AuthStep, Tokens};
use crate::sensitive_json::SensitiveClaims;
use crate::standard;
use crate::token::{self, Metadata};
use crate::transport::{CurlTransport, HttpTransport};

/// Public Keycloak client. The server requires no himmelcloak extension.
pub struct PublicClientApplication {
    config: Config,
    metadata: Metadata,
    transport: Arc<dyn HttpTransport>,
    jwks: RwLock<Value>,
}

impl PublicClientApplication {
    /// `server_url` is the Keycloak base URL, excluding `/realms/<realm>`.
    pub async fn new(server_url: &str, realm: &str, client_id: &str) -> Result<Self> {
        Self::with_config(Config::new(server_url, realm, client_id)?).await
    }

    pub async fn with_config(config: Config) -> Result<Self> {
        let transport = Arc::new(CurlTransport::new(
            config.ca_bundle.clone(),
            config.timeout,
        )?);
        Self::with_transport(config, transport).await
    }

    pub(crate) async fn with_transport(
        config: Config,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let metadata = token::discover(transport.as_ref(), &config.issuer()?).await?;
        let jwks = token::fetch_jwks(transport.as_ref(), metadata.jwks_uri.clone()).await?;
        Ok(Self {
            config,
            metadata,
            transport,
            jwks: RwLock::new(jwks),
        })
    }

    /// Direct Access Grant fast path. Returns an error if this Keycloak client disables it.
    pub async fn acquire_token_by_password(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<Tokens> {
        if !cfg!(feature = "password") {
            return Err(Error::UnsupportedFactor);
        }
        if totp.is_some() && !cfg!(feature = "totp") {
            return Err(Error::UnsupportedFactor);
        }
        let mut fields = vec![
            ("grant_type", "password"),
            ("client_id", self.config.client_id.as_str()),
            ("scope", "openid"),
            ("username", username),
            ("password", password),
        ];
        if let Some(code) = totp {
            fields.push(("totp", code));
        }
        let mut tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &fields,
            true,
        )
        .await?;
        let claims = self.verify_tokens(&tokens, None).await?;
        tokens.verified_subject = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
        tokens.verified_issuer = Some(self.metadata.issuer.clone());
        tokens.verified_client_id = Some(self.config.client_id.clone());
        tokens.verified_refresh_token = tokens.refresh_token.clone();
        Ok(tokens)
    }

    /// Refresh a verified session, retaining its subject when Keycloak omits a new ID token.
    pub async fn refresh_tokens(&self, previous: &Tokens) -> Result<Tokens> {
        let subject = self.session_subject(previous)?;
        let refresh_token = previous
            .refresh_token
            .as_deref()
            .ok_or(Error::Protocol("session has no refresh token"))?;
        if previous.verified_refresh_token.as_deref() != Some(refresh_token) {
            return Err(Error::TokenValidation("refresh token changed"));
        }
        let mut tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &[
                ("grant_type", "refresh_token"),
                ("client_id", self.config.client_id.as_str()),
                ("refresh_token", refresh_token),
            ],
            false,
        )
        .await?;
        if tokens.id_token.is_some() {
            let claims = self.verify_tokens(&tokens, None).await?;
            if claims.get("sub").and_then(Value::as_str) != Some(subject) {
                return Err(Error::TokenValidation("refreshed subject mismatch"));
            }
        } else {
            let user = standard::userinfo(
                self.transport.as_ref(),
                self.metadata.userinfo_endpoint.clone(),
                &tokens.access_token,
            )
            .await?;
            if user.get("sub").and_then(Value::as_str) != Some(subject) {
                return Err(Error::TokenValidation("refreshed subject mismatch"));
            }
        }
        if tokens.refresh_token.is_none() {
            tokens.refresh_token = Some(refresh_token.to_owned());
        }
        tokens.verified_subject = Some(subject.to_owned());
        tokens.verified_issuer = Some(self.metadata.issuer.clone());
        tokens.verified_client_id = Some(self.config.client_id.clone());
        tokens.verified_refresh_token = tokens.refresh_token.clone();
        Ok(tokens)
    }

    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        standard::revoke(
            self.transport.as_ref(),
            self.metadata.revocation_endpoint.clone(),
            &self.config.client_id,
            token,
        )
        .await
    }

    /// Fetch user information and require it to match the verified session subject.
    pub async fn userinfo(&self, tokens: &Tokens) -> Result<Value> {
        let subject = self.session_subject(tokens)?;
        if tokens.id_token.is_some() {
            let claims = self.verify_tokens(tokens, None).await?;
            if claims.get("sub").and_then(Value::as_str) != Some(subject) {
                return Err(Error::TokenValidation("session subject mismatch"));
            }
        }
        let user = standard::userinfo(
            self.transport.as_ref(),
            self.metadata.userinfo_endpoint.clone(),
            &tokens.access_token,
        )
        .await?;
        if user.get("sub").and_then(Value::as_str) != Some(subject) {
            return Err(Error::TokenValidation("userinfo subject mismatch"));
        }
        Ok(user.into_value())
    }

    fn session_subject<'a>(&self, tokens: &'a Tokens) -> Result<&'a str> {
        let subject = tokens
            .verified_subject
            .as_deref()
            .ok_or(Error::TokenValidation("unverified session"))?;
        if tokens.verified_issuer.as_deref() != Some(&self.metadata.issuer)
            || tokens.verified_client_id.as_deref() != Some(&self.config.client_id)
        {
            return Err(Error::TokenValidation("session issuer or client mismatch"));
        }
        Ok(subject)
    }

    pub(crate) async fn verify_tokens(
        &self,
        tokens: &Tokens,
        nonce: Option<&str>,
    ) -> Result<SensitiveClaims> {
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or(Error::TokenValidation("missing ID token"))?;
        let (kid, algorithm) = token::token_key_info(id_token)?;
        let known = self
            .jwks
            .read()
            .map_err(|_| Error::Protocol("JWKS lock poisoned"))
            .map(|jwks| token::jwks_has_eligible_key(&jwks, &kid, &algorithm))?;
        if !known {
            let fetched =
                token::fetch_jwks(self.transport.as_ref(), self.metadata.jwks_uri.clone()).await?;
            *self
                .jwks
                .write()
                .map_err(|_| Error::Protocol("JWKS lock poisoned"))? = fetched;
        }
        let jwks = self
            .jwks
            .read()
            .map_err(|_| Error::Protocol("JWKS lock poisoned"))?;
        token::verify_id_token(
            id_token,
            &jwks,
            &self.metadata.issuer,
            &self.config.client_id,
            nonce,
        )
    }

    pub(crate) fn authorization_url(&self, start: &Start, flow: &mut AuthFlow) -> Result<url::Url> {
        flow.ensure_active()?;
        token::authorization_url(
            &self.metadata.authorization_endpoint,
            token::AuthorizationParameters {
                client_id: &self.config.client_id,
                redirect_uri: &self.config.redirect_uri,
                login_hint: start.login_hint.as_deref(),
                scopes: &start.scopes,
                pkce_verifier: flow.pkce_verifier(),
                state: flow.oauth_state(),
                nonce: flow.nonce(),
            },
        )
    }

    /// Exchange the callback's code for tokens that pass the ID token checks, ending the login.
    /// A failed or abandoned exchange also ends it: the code is single-use.
    pub(crate) fn exchange_code<'a>(
        &'a self,
        callback: driver::Callback,
        flow: &'a mut AuthFlow,
    ) -> impl Future<Output = Result<Tokens>> + 'a {
        // Not an async fn: the guard must exist before the first poll, or an unpolled drop leaks it.
        let login = EndLogin(flow);
        async move {
            login.0.ensure_active()?;
            let tokens = self
                .redeem_code(&callback.code, login.0.pkce_verifier(), login.0.nonce())
                .await?;
            login.0.finish()?;
            Ok(tokens)
        }
    }

    /// Authorization-code grant for a public client (RFC 6749 section 4.1.3, RFC 7636 section 4.5).
    async fn redeem_code(&self, code: &str, verifier: &str, nonce: &str) -> Result<Tokens> {
        let mut tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &[
                ("grant_type", "authorization_code"),
                ("client_id", self.config.client_id.as_str()),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", verifier),
            ],
            true,
        )
        .await?;
        let claims = self.verify_tokens(&tokens, Some(nonce)).await?;
        tokens.verified_subject = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
        tokens.verified_issuer = Some(self.metadata.issuer.clone());
        tokens.verified_client_id = Some(self.config.client_id.clone());
        tokens.verified_refresh_token = tokens.refresh_token.clone();
        Ok(tokens)
    }

    pub async fn initiate_auth_flow(&self, _start: Start) -> Result<(AuthFlow, AuthStep)> {
        Err(Error::NotImplemented)
    }

    pub async fn continue_auth_flow(
        &self,
        flow: &mut AuthFlow,
        answer: Answer,
    ) -> Result<AuthStep> {
        driver::advance(flow, answer)
    }
}

/// Options for a native browser-flow login.
#[derive(Default)]
pub struct Start {
    pub login_hint: Option<String>,
    pub scopes: Vec<String>,
}

/// Ends the login when dropped, including when the caller drops an exchange mid-request.
struct EndLogin<'a>(&'a mut AuthFlow);

impl Drop for EndLogin<'_> {
    fn drop(&mut self) {
        // A finished login stays finished: cancel only changes an active flow.
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    use serde_json::{json, Value};
    use url::{form_urlencoded, Url};

    use super::{PublicClientApplication, Start};
    use crate::config::Config;
    use crate::error::{Error, Result};
    use crate::flow::driver::Callback;
    use crate::flow::Tokens;
    use crate::flow::{Answer, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
    use crate::token::Metadata;
    use crate::transport::{HttpTransport, Request, Response};

    struct RecordedTransport(Mutex<VecDeque<Response>>);

    impl HttpTransport for RecordedTransport {
        fn send(
            &self,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let response = self.0.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(response) })
        }
    }

    fn response(body: Value) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: serde_json::to_vec(&body).unwrap(),
            cookies: Vec::new(),
        }
    }

    fn app(jwks: Value, responses: Vec<Response>) -> PublicClientApplication {
        app_with(
            jwks,
            Arc::new(RecordedTransport(Mutex::new(responses.into()))),
        )
    }

    fn app_with(jwks: Value, transport: Arc<dyn HttpTransport>) -> PublicClientApplication {
        let config = Config::new("https://example.test", "test", "client").unwrap();
        let url = |path: &str| Url::parse(&format!("https://example.test/{path}")).unwrap();
        PublicClientApplication {
            config,
            metadata: Metadata {
                issuer: "https://example.test/realms/test".to_owned(),
                authorization_endpoint: url("auth"),
                token_endpoint: url("token"),
                jwks_uri: url("jwks"),
                userinfo_endpoint: url("userinfo"),
                revocation_endpoint: url("revoke"),
            },
            transport,
            jwks: RwLock::new(jwks),
        }
    }

    /// Answers from a script and records each request's URL and form body.
    struct TokenEndpoint {
        replies: Mutex<VecDeque<Result<Response>>>,
        sent: Mutex<Vec<(String, String)>>,
    }

    impl HttpTransport for TokenEndpoint {
        fn send(
            &self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let body = String::from_utf8(request.body.clone()).unwrap();
            self.sent
                .lock()
                .unwrap()
                .push((request.url.to_string(), body));
            let reply = self.replies.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { reply })
        }
    }

    /// Never answers, like a token endpoint that hangs.
    struct Stalled;

    impl HttpTransport for Stalled {
        fn send(
            &self,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    fn token_app(
        jwks: Value,
        replies: Vec<Result<Response>>,
    ) -> (PublicClientApplication, Arc<TokenEndpoint>) {
        let endpoint = Arc::new(TokenEndpoint {
            replies: Mutex::new(replies.into()),
            sent: Mutex::new(Vec::new()),
        });
        (app_with(jwks, endpoint.clone()), endpoint)
    }

    fn reply(status: u32, body: &str) -> Result<Response> {
        Ok(Response {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            cookies: Vec::new(),
        })
    }

    const FIXTURE_NONCE: &str = "fixture-login-nonce";

    fn nonce_fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token_nonce.json")).unwrap()
    }

    fn token_response(id_token: &Value) -> String {
        json!({
            "access_token": "access",
            "refresh_token": "refresh",
            "id_token": id_token,
            "token_type": "Bearer"
        })
        .to_string()
    }

    fn callback() -> Callback {
        Callback {
            code: "synthetic-code".to_owned(),
        }
    }

    fn sent_fields(endpoint: &TokenEndpoint) -> Vec<(String, String)> {
        let sent = endpoint.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "https://example.test/token");
        form_urlencoded::parse(sent[0].1.as_bytes())
            .into_owned()
            .collect()
    }

    #[tokio::test]
    async fn code_exchange_posts_the_pkce_grant_and_binds_the_session() {
        let fixture = nonce_fixture();
        let (client, endpoint) = token_app(
            fixture["jwk"].clone(),
            vec![reply(200, &token_response(&fixture["token"]))],
        );
        let tokens = client
            .redeem_code("synthetic-code", "synthetic-verifier", FIXTURE_NONCE)
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "access");
        assert_eq!(tokens.verified_subject.as_deref(), Some("alice"));
        assert_eq!(
            tokens.verified_issuer.as_deref(),
            Some("https://example.test/realms/test")
        );
        assert_eq!(tokens.verified_client_id.as_deref(), Some("client"));
        assert_eq!(tokens.verified_refresh_token.as_deref(), Some("refresh"));
        let expected = [
            ("grant_type", "authorization_code"),
            ("client_id", "client"),
            ("code", "synthetic-code"),
            ("redirect_uri", "http://127.0.0.1:8845/himmelcloak/callback"),
            ("code_verifier", "synthetic-verifier"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()));
        assert_eq!(sent_fields(&endpoint), expected);
    }

    #[tokio::test]
    async fn code_exchange_maps_token_endpoint_rejections() {
        let grant_setting =
            Error::InvalidConfiguration("Keycloak rejected the client or requested grant");
        let cases = [
            (
                reply(
                    400,
                    r#"{"error":"invalid_grant","error_description":"Code not valid"}"#,
                ),
                Error::AuthenticationRejected,
            ),
            (
                reply(400, r#"{"error":"invalid_client"}"#),
                grant_setting.clone(),
            ),
            (
                reply(400, r#"{"error":"unauthorized_client"}"#),
                grant_setting.clone(),
            ),
            (
                reply(400, r#"{"error":"unsupported_grant_type"}"#),
                grant_setting.clone(),
            ),
            (reply(400, r#"{"error":"invalid_request"}"#), grant_setting),
            (
                reply(400, r#"{"error":"server_error"}"#),
                Error::HttpStatus(400),
            ),
            (reply(401, "{}"), Error::AuthenticationRejected),
            (reply(500, ""), Error::HttpStatus(500)),
            (
                Err(Error::Transport("connection reset".to_owned())),
                Error::Transport("connection reset".to_owned()),
            ),
        ];
        for (answer, expected) in cases {
            let (client, _) = token_app(json!({}), vec![answer]);
            let want = Some(expected);
            assert_eq!(
                client
                    .redeem_code("wrong-code", "verifier", FIXTURE_NONCE)
                    .await
                    .err(),
                want,
                "{want:?}"
            );
        }
    }

    #[tokio::test]
    async fn code_exchange_rejects_malformed_token_responses() {
        let fixture = nonce_fixture();
        let id_token = fixture["token"].as_str().unwrap();
        let invalid = Error::Protocol("invalid token response");
        let wrong_type = Error::Protocol("unexpected token type");
        let cases = [
            ("not json".to_owned(), invalid.clone()),
            (
                json!({"token_type":"Bearer","id_token":id_token}).to_string(),
                invalid.clone(),
            ),
            (
                json!({"access_token":"access","id_token":id_token}).to_string(),
                invalid.clone(),
            ),
            (
                json!({"access_token":"access","token_type":"Bearer","id_token":7}).to_string(),
                invalid,
            ),
            (
                json!({"access_token":"access","token_type":"MAC","id_token":id_token}).to_string(),
                wrong_type.clone(),
            ),
            (
                json!({"access_token":"","token_type":"Bearer","id_token":id_token}).to_string(),
                wrong_type,
            ),
            (
                json!({"access_token":"access","token_type":"Bearer"}).to_string(),
                Error::Protocol("token response has no ID token"),
            ),
        ];
        for (body, expected) in cases {
            let (client, _) = token_app(fixture["jwk"].clone(), vec![reply(200, &body)]);
            assert_eq!(
                client
                    .redeem_code("code", "verifier", FIXTURE_NONCE)
                    .await
                    .err(),
                Some(expected),
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn code_exchange_requires_the_nonce_this_login_sent() {
        let bound = nonce_fixture();
        let unbound: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        for (fixture, nonce) in [(&bound, "another-login-nonce"), (&unbound, FIXTURE_NONCE)] {
            let (client, _) = token_app(
                fixture["jwk"].clone(),
                vec![reply(200, &token_response(&fixture["token"]))],
            );
            assert_eq!(
                client.redeem_code("code", "verifier", nonce).await.err(),
                Some(Error::TokenValidation("nonce mismatch"))
            );
        }
    }

    #[tokio::test]
    async fn code_exchange_applies_the_id_token_checks() {
        let fixture = nonce_fixture();
        let (mut other_client, _) = token_app(
            fixture["jwk"].clone(),
            vec![reply(200, &token_response(&fixture["token"]))],
        );
        other_client.config.client_id = "another-client".to_owned();
        assert_eq!(
            other_client
                .redeem_code("code", "verifier", FIXTURE_NONCE)
                .await
                .err(),
            Some(Error::TokenValidation("audience mismatch"))
        );

        let mut tampered = fixture["token"].as_str().unwrap().as_bytes().to_vec();
        let signature_start = tampered.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
        tampered[signature_start] = b"BA"[usize::from(tampered[signature_start] != b'A')];
        let tampered = String::from_utf8(tampered).unwrap();
        let (client, _) = token_app(
            fixture["jwk"].clone(),
            vec![reply(200, &token_response(&json!(tampered)))],
        );
        assert_eq!(
            client
                .redeem_code("code", "verifier", FIXTURE_NONCE)
                .await
                .err(),
            Some(Error::TokenValidation("invalid signature"))
        );
    }

    #[tokio::test]
    async fn code_exchange_sends_nothing_for_an_ended_login() {
        let mut cancelled = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        cancelled.cancel();
        let mut expired = AuthFlow::new(Duration::ZERO).unwrap();
        let mut finished = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        finished.finish().unwrap();
        for (flow, expected) in [
            (&mut cancelled, Error::Cancelled),
            (&mut expired, Error::Expired),
            (
                &mut finished,
                Error::Protocol("login flow already finished"),
            ),
        ] {
            let (client, endpoint) = token_app(json!({}), vec![]);
            assert_eq!(
                client.exchange_code(callback(), flow).await.err(),
                Some(expected)
            );
            assert!(endpoint.sent.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn code_exchange_finishes_the_login_with_verified_tokens() {
        let fixture = nonce_fixture();
        let (client, endpoint) = token_app(
            fixture["jwk"].clone(),
            vec![reply(200, &token_response(&fixture["token"]))],
        );
        let mut flow = AuthFlow::with_nonce(DEFAULT_LOGIN_TIMEOUT, FIXTURE_NONCE).unwrap();
        let verifier = flow.pkce_verifier().to_owned();
        let tokens = client.exchange_code(callback(), &mut flow).await.unwrap();
        assert_eq!(tokens.verified_subject.as_deref(), Some("alice"));
        let fields: HashMap<_, _> = sent_fields(&endpoint).into_iter().collect();
        assert_eq!(fields["code_verifier"], verifier);
        assert_eq!(
            flow.ensure_active().err(),
            Some(Error::Protocol("login flow already finished"))
        );
        assert!(flow.pkce_verifier().is_empty() && flow.nonce().is_empty());
    }

    #[tokio::test]
    async fn an_abandoned_code_exchange_ends_the_login() {
        let client = app_with(json!({}), Arc::new(Stalled));
        let mut never_polled = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        drop(client.exchange_code(callback(), &mut never_polled));
        let mut timed_out = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        let exchange = client.exchange_code(callback(), &mut timed_out);
        assert!(tokio::time::timeout(Duration::from_millis(10), exchange)
            .await
            .is_err());
        for flow in [&mut never_polled, &mut timed_out] {
            assert_eq!(flow.ensure_active().err(), Some(Error::Cancelled));
            assert!(flow.pkce_verifier().is_empty() && flow.nonce().is_empty());
        }
    }

    #[tokio::test]
    async fn code_exchange_sends_the_login_verifier_and_ends_a_failed_login() {
        let fixture = nonce_fixture();
        let cases = [
            (
                reply(400, r#"{"error":"invalid_grant"}"#),
                Error::AuthenticationRejected,
            ),
            // Signed and nonce-bound, but not to this login's random nonce.
            (
                reply(200, &token_response(&fixture["token"])),
                Error::TokenValidation("nonce mismatch"),
            ),
        ];
        for (answer, expected) in cases {
            let (client, endpoint) = token_app(fixture["jwk"].clone(), vec![answer]);
            let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
            let verifier = flow.pkce_verifier().to_owned();
            assert_eq!(
                client.exchange_code(callback(), &mut flow).await.err(),
                Some(expected)
            );
            let fields: HashMap<_, _> = sent_fields(&endpoint).into_iter().collect();
            assert_eq!(fields["code"], "synthetic-code");
            assert_eq!(fields["code_verifier"], verifier);
            assert_eq!(flow.ensure_active().err(), Some(Error::Cancelled));
            assert!(flow.pkce_verifier().is_empty() && flow.nonce().is_empty());
        }
    }

    #[test]
    fn authorization_request_uses_the_flow_secrets() {
        let client = app(json!({}), vec![]);
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        let start = Start {
            login_hint: Some("alice@example.test".to_owned()),
            scopes: vec!["profile".to_owned()],
        };
        let url = client.authorization_url(&start, &mut flow).unwrap();
        let parameters: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(parameters.get("state").unwrap(), flow.oauth_state());
        assert_eq!(parameters.get("nonce").unwrap(), flow.nonce());
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(parameters.get("scope").unwrap(), "openid profile");
        assert_eq!(parameters.get("login_hint").unwrap(), "alice@example.test");

        let mut ended = flow;
        ended.cancel();
        assert!(client.authorization_url(&start, &mut ended).is_err());

        let mut expired = AuthFlow::new(Duration::ZERO).unwrap();
        assert_eq!(
            client.authorization_url(&start, &mut expired).err(),
            Some(Error::Expired)
        );
    }

    #[cfg(feature = "password")]
    #[tokio::test]
    async fn refresh_without_id_token_preserves_verified_userinfo_subject() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let client = app(
            fixture["jwk"].clone(),
            vec![
                response(json!({
                    "access_token": "original-access",
                    "refresh_token": "original-refresh",
                    "id_token": fixture["token"],
                    "token_type": "Bearer"
                })),
                response(json!({"access_token":"new-access","token_type":"Bearer"})),
                response(json!({"sub":"alice"})),
                response(json!({"sub":"alice"})),
                response(json!({"sub":"mallory","private":{"name":"hidden"}})),
            ],
        );
        let original = client
            .acquire_token_by_password("alice", "test-password", None)
            .await
            .unwrap();
        let refreshed = client.refresh_tokens(&original).await.unwrap();
        assert_eq!(refreshed.access_token, "new-access");
        assert_eq!(refreshed.refresh_token.as_deref(), Some("original-refresh"));
        assert!(refreshed.id_token.is_none());
        assert_eq!(client.userinfo(&refreshed).await.unwrap()["sub"], "alice");
        assert_eq!(
            client.userinfo(&refreshed).await.err(),
            Some(Error::TokenValidation("userinfo subject mismatch"))
        );
    }

    #[tokio::test]
    async fn refresh_rejects_a_signed_id_token_for_another_subject() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let client = app(
            fixture["jwk"].clone(),
            vec![response(json!({
                "access_token": "new-access",
                "id_token": fixture["token"],
                "token_type": "Bearer"
            }))],
        );
        let previous = Tokens {
            access_token: "previous-access".to_owned(),
            refresh_token: Some("previous-refresh".to_owned()),
            id_token: None,
            verified_subject: Some("mallory".to_owned()),
            verified_issuer: Some("https://example.test/realms/test".to_owned()),
            verified_client_id: Some("client".to_owned()),
            verified_refresh_token: Some("previous-refresh".to_owned()),
        };
        assert_eq!(
            client.refresh_tokens(&previous).await.err(),
            Some(Error::TokenValidation("refreshed subject mismatch"))
        );
    }

    #[tokio::test]
    async fn refresh_rejects_an_access_token_for_another_subject_without_an_id_token() {
        let client = app(
            json!({}),
            vec![
                response(json!({"access_token":"other-access","token_type":"Bearer"})),
                response(json!({"sub":"mallory"})),
            ],
        );
        let previous = Tokens {
            access_token: "alice-access".to_owned(),
            refresh_token: Some("alice-refresh".to_owned()),
            id_token: None,
            verified_subject: Some("alice".to_owned()),
            verified_issuer: Some("https://example.test/realms/test".to_owned()),
            verified_client_id: Some("client".to_owned()),
            verified_refresh_token: Some("alice-refresh".to_owned()),
        };
        assert_eq!(
            client.refresh_tokens(&previous).await.err(),
            Some(Error::TokenValidation("refreshed subject mismatch"))
        );
    }

    #[tokio::test]
    async fn refresh_rejects_a_swapped_refresh_token_without_an_id_token() {
        let client = app(serde_json::json!({}), vec![]);
        let previous = Tokens {
            access_token: "alice-access".to_owned(),
            refresh_token: Some("bob-refresh".to_owned()),
            id_token: None,
            verified_subject: Some("alice".to_owned()),
            verified_issuer: Some("https://example.test/realms/test".to_owned()),
            verified_client_id: Some("client".to_owned()),
            verified_refresh_token: Some("alice-refresh".to_owned()),
        };
        assert_eq!(
            client.refresh_tokens(&previous).await.err(),
            Some(Error::TokenValidation("refresh token changed"))
        );
    }

    #[tokio::test]
    async fn sessions_never_send_tokens_to_another_issuer_or_client() {
        let tokens = Tokens {
            access_token: "alice-access".to_owned(),
            refresh_token: Some("alice-refresh".to_owned()),
            id_token: None,
            verified_subject: Some("alice".to_owned()),
            verified_issuer: Some("https://example.test/realms/test".to_owned()),
            verified_client_id: Some("client".to_owned()),
            verified_refresh_token: Some("alice-refresh".to_owned()),
        };
        let mut wrong_client = app(json!({}), vec![]);
        wrong_client.config.client_id = "another-client".to_owned();
        let mut wrong_issuer = app(json!({}), vec![]);
        wrong_issuer.metadata.issuer = "https://other.test/realms/test".to_owned();
        for client in [&wrong_client, &wrong_issuer] {
            assert_eq!(
                client.refresh_tokens(&tokens).await.err(),
                Some(Error::TokenValidation("session issuer or client mismatch"))
            );
            assert_eq!(
                client.userinfo(&tokens).await.err(),
                Some(Error::TokenValidation("session issuer or client mismatch"))
            );
        }
    }

    #[tokio::test]
    async fn refresh_keeps_a_rotated_token_available_for_the_next_refresh() {
        let client = app(
            serde_json::json!({}),
            vec![
                response(json!({
                    "access_token": "first-access",
                    "refresh_token": "first-refresh",
                    "token_type": "Bearer"
                })),
                response(json!({"sub":"alice"})),
                response(json!({
                    "access_token": "second-access",
                    "refresh_token": "second-refresh",
                    "token_type": "Bearer"
                })),
                response(json!({"sub":"alice"})),
            ],
        );
        let previous = Tokens {
            access_token: "original-access".to_owned(),
            refresh_token: Some("original-refresh".to_owned()),
            id_token: None,
            verified_subject: Some("alice".to_owned()),
            verified_issuer: Some("https://example.test/realms/test".to_owned()),
            verified_client_id: Some("client".to_owned()),
            verified_refresh_token: Some("original-refresh".to_owned()),
        };
        let first = client.refresh_tokens(&previous).await.unwrap();
        assert_eq!(first.refresh_token.as_deref(), Some("first-refresh"));
        let second = client.refresh_tokens(&first).await.unwrap();
        assert_eq!(second.refresh_token.as_deref(), Some("second-refresh"));
    }

    #[cfg(not(feature = "password"))]
    #[tokio::test]
    async fn password_grant_requires_password_feature() {
        let client = app(serde_json::json!({}), vec![]);
        assert_eq!(
            client
                .acquire_token_by_password("alice", "password", None)
                .await
                .err(),
            Some(Error::UnsupportedFactor)
        );
    }

    #[cfg(all(feature = "password", not(feature = "totp")))]
    #[tokio::test]
    async fn password_grant_rejects_totp_without_its_feature() {
        let client = app(serde_json::json!({}), vec![]);
        assert_eq!(
            client
                .acquire_token_by_password("alice", "password", Some("123456"))
                .await
                .err(),
            Some(Error::UnsupportedFactor)
        );
    }

    fn password() -> Answer {
        Answer::Password("correct-horse-battery-staple".to_owned())
    }

    #[tokio::test]
    async fn continue_rejects_a_cancelled_login() {
        let client = app(json!({}), vec![]);
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        assert_eq!(
            client.continue_auth_flow(&mut flow, password()).await.err(),
            Some(Error::NotImplemented)
        );
        flow.cancel();
        assert_eq!(
            client.continue_auth_flow(&mut flow, password()).await.err(),
            Some(Error::Cancelled)
        );
    }

    #[tokio::test]
    async fn continue_rejects_an_expired_login() {
        let client = app(json!({}), vec![]);
        let mut flow = AuthFlow::new(Duration::ZERO).unwrap();
        assert_eq!(
            client.continue_auth_flow(&mut flow, password()).await.err(),
            Some(Error::Expired)
        );
    }

    #[tokio::test]
    async fn refetches_jwks_for_a_new_signing_key() {
        let rs: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let es: Value =
            serde_json::from_str(include_str!("../tests/fixtures/es256_id_token.json")).unwrap();
        let tokens = Tokens {
            access_token: String::new(),
            refresh_token: None,
            id_token: Some(rs["token"].as_str().unwrap().to_owned()),
            verified_subject: None,
            verified_issuer: None,
            verified_client_id: None,
            verified_refresh_token: None,
        };
        let good = app(es["jwk"].clone(), vec![response(rs["jwk"].clone())]);
        assert_eq!(
            good.verify_tokens(&tokens, None).await.unwrap()["sub"],
            "alice"
        );

        let stale = app(es["jwk"].clone(), vec![response(es["jwk"].clone())]);
        assert_eq!(
            stale.verify_tokens(&tokens, None).await.err(),
            Some(Error::TokenValidation("unknown key ID"))
        );

        let mut incompatible = rs["jwk"].clone();
        incompatible["keys"][0]["alg"] = json!("RS384");
        let same_id_wrong_algorithm = app(incompatible, vec![response(rs["jwk"].clone())]);
        assert_eq!(
            same_id_wrong_algorithm
                .verify_tokens(&tokens, None)
                .await
                .unwrap()["sub"],
            "alice"
        );
    }
}
