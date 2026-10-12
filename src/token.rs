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
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};
use crate::sensitive_json::{parse as parse_sensitive_json, SensitiveClaims};
use crate::transport::{HttpTransport, Request};

#[derive(Clone)]
pub(crate) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    pub userinfo_endpoint: Url,
    pub revocation_endpoint: Url,
}

#[derive(Deserialize)]
struct RawMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
}

pub(crate) async fn discover(
    transport: &dyn HttpTransport,
    expected_issuer: &Url,
) -> Result<Metadata> {
    let discovery_url = Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        expected_issuer.as_str().trim_end_matches('/')
    ))
    .map_err(|_| Error::Protocol("invalid discovery URL"))?;
    let response = transport.send(Request::get(discovery_url)).await?;
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let raw: RawMetadata = serde_json::from_slice(&response.body)
        .map_err(|_| Error::Protocol("invalid discovery document"))?;
    if raw.issuer != expected_issuer.as_str().trim_end_matches('/') {
        return Err(Error::Protocol("discovered issuer mismatch"));
    }
    Ok(Metadata {
        issuer: raw.issuer,
        authorization_endpoint: endpoint(&raw.authorization_endpoint, expected_issuer)?,
        token_endpoint: endpoint(&raw.token_endpoint, expected_issuer)?,
        jwks_uri: endpoint(&raw.jwks_uri, expected_issuer)?,
        userinfo_endpoint: endpoint(&raw.userinfo_endpoint, expected_issuer)?,
        revocation_endpoint: endpoint(&raw.revocation_endpoint, expected_issuer)?,
    })
}

fn endpoint(raw: &str, issuer: &Url) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| Error::Protocol("invalid OIDC endpoint"))?;
    if url.scheme() != "https" || url.origin() != issuer.origin() {
        return Err(Error::Protocol("OIDC endpoint origin mismatch"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Protocol("OIDC endpoint contains credentials"));
    }
    if url.fragment().is_some() {
        return Err(Error::Protocol("OIDC endpoint contains fragment"));
    }
    // Same origin still allows another realm on the same server. The issuer ends in
    // /realms/<realm>, so take that realm and require the endpoint to sit under it.
    // Matching the realm, not the whole path, lets the frontend issuer and the
    // backchannel endpoints use different context paths.
    if issuer_realm(issuer.path()).is_some_and(|realm| !endpoint_in_realm(url.path(), realm)) {
        return Err(Error::Protocol("OIDC endpoint outside issuer realm"));
    }
    Ok(url)
}

pub(crate) struct AuthorizationParameters<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a Url,
    pub login_hint: Option<&'a str>,
    pub scopes: &'a [String],
    pub pkce_verifier: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
}

pub(crate) fn authorization_url(
    endpoint: &Url,
    parameters: AuthorizationParameters<'_>,
) -> Result<Url> {
    let AuthorizationParameters {
        client_id,
        redirect_uri,
        login_hint,
        scopes,
        pkce_verifier,
        state,
        nonce,
    } = parameters;
    // The endpoint must not pre-set a parameter we append, nor request/request_uri/
    // response_mode, which would override the request we build.
    const RESERVED_PARAMETERS: [&str; 12] = [
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "state",
        "nonce",
        "login_hint",
        "response_mode",
        "request",
        "request_uri",
    ];
    if endpoint
        .query_pairs()
        .any(|(name, _)| RESERVED_PARAMETERS.contains(&name.as_ref()))
    {
        return Err(Error::Protocol(
            "authorization endpoint parameter collision",
        ));
    }
    if !valid_pkce_verifier(pkce_verifier)
        || !valid_request_token(state)
        || !valid_request_token(nonce)
    {
        return Err(Error::Protocol("invalid authorization request secret"));
    }

    let mut normalized_scopes = vec!["openid"];
    for scope in scopes {
        if !valid_scope_token(scope) {
            return Err(Error::Protocol("invalid authorization scope"));
        }
        if scope != "openid" && !normalized_scopes.contains(&scope.as_str()) {
            normalized_scopes.push(scope);
        }
    }
    let scope = normalized_scopes.join(" ");
    let challenge = pkce_challenge(pkce_verifier)?;
    let mut url = endpoint.clone();
    let mut query = url.query_pairs_mut();
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("scope", &scope)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("nonce", nonce);
    if let Some(login_hint) = login_hint {
        query.append_pair("login_hint", login_hint);
    }
    drop(query);
    Ok(url)
}

fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_request_token(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn pkce_challenge(verifier: &str) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(crypto::sha256(verifier.as_bytes())?))
}

// The realm an issuer names: its last path segment, when that segment follows a
// "realms" segment. Config::issuer always appends /realms/<realm>, so the realm is
// unambiguous here however the server's context path is shaped.
fn issuer_realm(path: &str) -> Option<&str> {
    let mut previous = None;
    let mut last = None;
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        previous = last;
        last = Some(segment);
    }
    match (previous, last) {
        (Some("realms"), realm @ Some(_)) => realm,
        _ => None,
    }
}

// Whether an endpoint path is scoped to `realm`: its deepest realms/<realm> pair
// names `realm`, with no further "realms" segment after it that would start another.
fn endpoint_in_realm(path: &str, realm: &str) -> bool {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    // rposition gives the index of the "realms" segment, so the realm value is next.
    segments
        .windows(2)
        .rposition(|pair| pair[0] == "realms" && pair[1] == realm)
        .is_some_and(|at| {
            // Nothing after the realm may start another realm. A percent-encoded segment
            // could hide one, and Keycloak's resource path has neither, so reject both.
            segments[at + 2..]
                .iter()
                .all(|segment| *segment != "realms" && !segment.contains('%'))
        })
}

pub(crate) async fn fetch_jwks(transport: &dyn HttpTransport, url: Url) -> Result<Value> {
    let response = transport.send(Request::get(url)).await?;
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let jwks: Value =
        serde_json::from_slice(&response.body).map_err(|_| Error::Protocol("invalid JWKS"))?;
    if jwks
        .get("keys")
        .and_then(Value::as_array)
        .is_none_or(|keys| keys.is_empty())
    {
        return Err(Error::Protocol("JWKS has no keys"));
    }
    Ok(jwks)
}

pub(crate) fn token_key_info(token: &str) -> Result<(String, String)> {
    let (header, _, _) = split_token(token)?;
    let header = decode_json(header)?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::TokenValidation("token has no key ID"))?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing algorithm"))?;
    if !matches!(algorithm, "RS256" | "ES256") {
        return Err(Error::TokenValidation("unsupported signing algorithm"));
    }
    Ok((kid, algorithm.to_owned()))
}

fn key_eligible(key: &Value, kid: &str, algorithm: &str) -> bool {
    let string_field_matches = |name: &str, expected: &str| {
        key.get(name).is_none() || key.get(name).and_then(Value::as_str) == Some(expected)
    };
    let type_matches = match algorithm {
        "RS256" => key.get("kty").and_then(Value::as_str) == Some("RSA"),
        "ES256" => {
            key.get("kty").and_then(Value::as_str) == Some("EC")
                && key.get("crv").and_then(Value::as_str) == Some("P-256")
        }
        _ => false,
    };
    key.get("kid").and_then(Value::as_str) == Some(kid)
        && string_field_matches("use", "sig")
        && string_field_matches("alg", algorithm)
        && key.get("key_ops").is_none_or(|ops| {
            ops.as_array().is_some_and(|ops| {
                ops.iter().any(|op| op.as_str() == Some("verify"))
                    && ops.iter().all(Value::is_string)
            })
        })
        && type_matches
}

pub(crate) fn jwks_has_eligible_key(jwks: &Value, kid: &str, algorithm: &str) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.iter().any(|key| key_eligible(key, kid, algorithm)))
}

pub(crate) fn verify_id_token(
    token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<SensitiveClaims> {
    let (header, claims, signature) = split_token(token)?;
    let header_json = decode_json(header)?;
    let claims_json = decode_json(claims)?;
    let algorithm = header_json
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing algorithm"))?;
    if !matches!(algorithm, "RS256" | "ES256") {
        return Err(Error::TokenValidation("unsupported signing algorithm"));
    }
    let kid = header_json
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing key ID"))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::TokenValidation("invalid JWKS"))?;
    let mut message = Zeroizing::new(Vec::with_capacity(header.len() + claims.len() + 1));
    message.extend_from_slice(header.as_bytes());
    message.push(b'.');
    message.extend_from_slice(claims.as_bytes());
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error::TokenValidation("invalid signature encoding"))?;
    let mut eligible = false;
    for key in keys.iter().filter(|key| key_eligible(key, kid, algorithm)) {
        eligible = true;
        match crypto::verify(algorithm, key, &message, &signature) {
            Ok(()) => {
                validate_claims(&claims_json, issuer, client_id, nonce)?;
                return Ok(claims_json);
            }
            Err(Error::Crypto) => return Err(Error::Crypto),
            Err(_) => {}
        }
    }
    if !eligible {
        return Err(
            if keys
                .iter()
                .any(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
            {
                Error::TokenValidation("JWK not valid for token signature")
            } else {
                Error::TokenValidation("unknown key ID")
            },
        );
    }
    Err(Error::TokenValidation("invalid signature"))
}

fn validate_claims(
    claims_json: &Value,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<()> {
    if claims_json.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(Error::TokenValidation("issuer mismatch"));
    }
    if !audience_matches(claims_json, client_id) {
        return Err(Error::TokenValidation("audience mismatch"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TokenValidation("clock before epoch"))?
        .as_secs();
    let expiry = claims_json
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(Error::TokenValidation("missing expiry"))?;
    if expiry <= now {
        return Err(Error::TokenValidation("token expired"));
    }
    if let Some(nbf) = claims_json.get("nbf") {
        let nbf = nbf
            .as_u64()
            .ok_or(Error::TokenValidation("invalid not-before time"))?;
        if nbf > now.saturating_add(60) {
            return Err(Error::TokenValidation("token not yet valid"));
        }
    }
    let issued_at = claims_json
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(Error::TokenValidation("missing issued-at time"))?;
    if issued_at > now.saturating_add(60) {
        return Err(Error::TokenValidation("token issued in future"));
    }
    if nonce
        .is_some_and(|expected| claims_json.get("nonce").and_then(Value::as_str) != Some(expected))
    {
        return Err(Error::TokenValidation("nonce mismatch"));
    }
    if claims_json
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::TokenValidation("missing subject"));
    }
    Ok(())
}

fn audience_matches(claims: &Value, client_id: &str) -> bool {
    match claims.get("azp") {
        None => {}
        Some(Value::String(azp)) if azp == client_id => {}
        _ => return false,
    }
    match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(aud)) => {
            let valid = aud.iter().all(Value::is_string);
            let contains = aud.iter().any(|item| item.as_str() == Some(client_id));
            valid
                && contains
                && (aud.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => false,
    }
}

fn split_token(token: &str) -> Result<(&str, &str, &str)> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(claims), Some(signature), None)
            if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
        {
            Ok((header, claims, signature))
        }
        _ => Err(Error::TokenValidation("malformed JWT")),
    }
}

fn decode_json(part: &str) -> Result<SensitiveClaims> {
    // Keep the entire output slice live and zeroizing even when decoding fails
    // after writing a valid prefix. Its length also covers the decoder's
    // conservative estimate, so no plaintext can land in spare capacity.
    let mut bytes = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(part.len())]);
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(part, &mut bytes[..])
        .map_err(|_| Error::TokenValidation("invalid JWT encoding"))?;
    parse_sensitive_json(&bytes[..decoded]).ok_or(Error::TokenValidation("invalid JWT JSON"))
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use serde_json::json;

    use super::{
        audience_matches, authorization_url, decode_json, discover, endpoint,
        jwks_has_eligible_key, pkce_challenge, token_key_info, validate_claims, verify_id_token,
        AuthorizationParameters,
    };
    use crate::error::{Error, Result};
    use crate::sensitive_json::clear_claims;
    use crate::transport::{HttpTransport, Request, Response};
    use url::Url;

    struct RecordedTransport(Mutex<Option<Response>>);

    #[test]
    fn clears_nested_identity_claims() {
        let mut claims = json!(["alice", ["private-attribute"]]);
        clear_claims(&mut claims);
        assert_eq!(claims[0].as_str(), Some(""));
        assert_eq!(claims[1][0].as_str(), Some(""));

        let mut object = json!({"custom-claim": "private-value"});
        clear_claims(&mut object);
        assert!(object.as_object().unwrap().is_empty());
    }

    #[test]
    fn rejects_late_invalid_base64_in_claims() {
        let segment = format!("{}!", "QUJD".repeat(512));
        assert_eq!(
            decode_json(&segment).err(),
            Some(Error::TokenValidation("invalid JWT encoding"))
        );
    }

    impl HttpTransport for RecordedTransport {
        fn send(
            &self,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let response = self.0.lock().unwrap().take().unwrap();
            Box::pin(async move { Ok(response) })
        }
    }

    fn discovery_document(issuer: &Url) -> serde_json::Value {
        json!({
            "issuer": issuer.as_str(),
            "authorization_endpoint": "https://login.example/realms/test/auth",
            "token_endpoint": "https://login.example/realms/test/token",
            "jwks_uri": "https://login.example/realms/test/keys",
            "userinfo_endpoint": "https://login.example/realms/test/userinfo",
            "revocation_endpoint": "https://login.example/realms/test/revoke"
        })
    }

    async fn discover_body(body: Vec<u8>, issuer: &Url) -> Result<super::Metadata> {
        let transport = RecordedTransport(Mutex::new(Some(Response {
            status: 200,
            headers: Vec::new(),
            body,
            cookies: Vec::new(),
        })));
        discover(&transport, issuer).await
    }

    #[test]
    fn derives_the_rfc_7636_s256_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier).unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn builds_the_authorization_request() {
        let endpoint = Url::parse("https://login.example/auth?kc_idp_hint=company").unwrap();
        let redirect = Url::parse("http://127.0.0.1:8845/himmelcloak/callback").unwrap();
        let scopes = ["profile", "openid", "email", "profile"].map(str::to_owned);
        let url = authorization_url(
            &endpoint,
            AuthorizationParameters {
                client_id: "native client",
                redirect_uri: &redirect,
                login_hint: Some("alice+admin@example.test"),
                scopes: &scopes,
                pkce_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                state: "abcdefghijklmnopqrstuv",
                nonce: "ABCDEFGHIJKLMNOPQRSTUV",
            },
        )
        .unwrap();
        let parameters: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(parameters.get("kc_idp_hint").unwrap(), "company");
        assert_eq!(parameters.get("response_type").unwrap(), "code");
        assert_eq!(parameters.get("client_id").unwrap(), "native client");
        assert_eq!(parameters.get("redirect_uri").unwrap(), redirect.as_str());
        assert_eq!(parameters.get("scope").unwrap(), "openid profile email");
        assert_eq!(
            parameters.get("code_challenge").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(parameters.get("state").unwrap(), "abcdefghijklmnopqrstuv");
        assert_eq!(parameters.get("nonce").unwrap(), "ABCDEFGHIJKLMNOPQRSTUV");
        assert_eq!(
            parameters.get("login_hint").unwrap(),
            "alice+admin@example.test"
        );
    }

    #[test]
    fn rejects_invalid_scopes_and_owned_parameter_collisions() {
        let endpoint = Url::parse("https://login.example/auth").unwrap();
        let redirect = Url::parse("http://127.0.0.1:8845/himmelcloak/callback").unwrap();
        let build = |endpoint: &Url, scopes: &[String]| {
            authorization_url(
                endpoint,
                AuthorizationParameters {
                    client_id: "client",
                    redirect_uri: &redirect,
                    login_hint: None,
                    scopes,
                    pkce_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    state: "abcdefghijklmnopqrstuv",
                    nonce: "ABCDEFGHIJKLMNOPQRSTUV",
                },
            )
        };
        for invalid in ["", "profile email", "bad\"scope", "bad\\scope", "café"] {
            assert!(
                build(&endpoint, &[invalid.to_owned()]).is_err(),
                "{invalid}"
            );
        }
        for parameter in [
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "code_challenge",
            "code_challenge_method",
            "state",
            "nonce",
            "login_hint",
            "response_mode",
            "request",
            "request_uri",
        ] {
            let endpoint =
                Url::parse(&format!("https://login.example/auth?{parameter}=attacker")).unwrap();
            assert_eq!(
                build(&endpoint, &[]).err(),
                Some(Error::Protocol(
                    "authorization endpoint parameter collision"
                )),
                "{parameter}"
            );
        }
    }

    #[test]
    fn rejects_invalid_authorization_request_secrets() {
        let endpoint = Url::parse("https://login.example/auth").unwrap();
        let redirect = Url::parse("http://127.0.0.1:8845/himmelcloak/callback").unwrap();
        let build = |verifier: &str, state: &str, nonce: &str| {
            authorization_url(
                &endpoint,
                AuthorizationParameters {
                    client_id: "client",
                    redirect_uri: &redirect,
                    login_hint: None,
                    scopes: &[],
                    pkce_verifier: verifier,
                    state,
                    nonce,
                },
            )
        };
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let state = "abcdefghijklmnopqrstuv";
        let nonce = "ABCDEFGHIJKLMNOPQRSTUV";
        assert!(build("short", state, nonce).is_err());
        assert!(build(verifier, "", nonce).is_err());
        assert!(build(verifier, state, "").is_err());
    }

    #[test]
    fn discovery_endpoint_must_keep_the_issuer_origin() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/realms/test/protocol/openid-connect/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint("https://elsewhere.example/token", &issuer).is_err());
        assert!(endpoint("http://login.example/token", &issuer).is_err());
        assert!(endpoint("https://login.example/token#fragment", &issuer).is_err());
        assert!(endpoint("https://user@login.example/token", &issuer).is_err());
        assert!(endpoint("https://user:secret@login.example/token", &issuer).is_err());
        // Same origin, different realm: must be rejected.
        assert!(endpoint("https://login.example/realms/other/token", &issuer).is_err());
        assert!(endpoint("https://login.example/realms/testing/token", &issuer).is_err());
        // Same realm under a different backchannel context path: allowed.
        assert!(endpoint("https://login.example/private/realms/test/token", &issuer).is_ok());
    }

    #[test]
    fn endpoint_realm_survives_realms_in_the_context_path() {
        // Server context paths that themselves contain a "realms" segment.
        let issuer = Url::parse("https://login.example/realms/proxy/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/realms/proxy/realms/test/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint("https://login.example/private/realms/test/token", &issuer).is_ok());
        assert!(endpoint(
            "https://login.example/realms/proxy/realms/other/token",
            &issuer
        )
        .is_err());

        let issuer = Url::parse("https://login.example/proxy/realms/gateway/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/proxy/realms/gateway/realms/test/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint(
            "https://login.example/proxy/realms/gateway/realms/other/token",
            &issuer
        )
        .is_err());

        // Server context path that ends in "/realms".
        let issuer = Url::parse("https://login.example/realms/realms/test").unwrap();
        assert!(endpoint("https://login.example/realms/realms/test/token", &issuer).is_ok());
        assert!(endpoint("https://login.example/realms/realms/other/token", &issuer).is_err());

        // Server context path that is itself "/realms/<realm>".
        let issuer = Url::parse("https://login.example/realms/test/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/realms/test/realms/test/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint(
            "https://login.example/realms/test/realms/other/token",
            &issuer
        )
        .is_err());

        // A percent-encoded "realms" marker must not slip a different realm past the check.
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/realms/test/%72ealms/other/token",
            &issuer
        )
        .is_err());

        // A realm name with a reserved character is percent-encoded the same way on
        // both sides, so a legitimate endpoint still matches.
        let issuer = Url::parse("https://login.example/realms/my%20realm").unwrap();
        assert!(endpoint("https://login.example/realms/my%20realm/token", &issuer).is_ok());
        assert!(endpoint("https://login.example/realms/other/token", &issuer).is_err());

        // A realm literally named "realms" validates for its own endpoints.
        let issuer = Url::parse("https://login.example/realms/realms").unwrap();
        assert!(endpoint(
            "https://login.example/realms/realms/protocol/openid-connect/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint("https://login.example/realms/other/token", &issuer).is_err());
    }

    #[tokio::test]
    async fn discovery_rejects_malformed_documents() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        for body in [b"{".to_vec(), b"[]".to_vec(), b"null".to_vec()] {
            assert!(discover_body(body, &issuer).await.is_err());
        }

        let fields = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "revocation_endpoint",
        ];
        for field in fields {
            let mut missing = discovery_document(&issuer);
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                discover_body(serde_json::to_vec(&missing).unwrap(), &issuer)
                    .await
                    .is_err(),
                "missing {field}"
            );
            for invalid in [serde_json::Value::Null, json!(7)] {
                let mut wrong_type = discovery_document(&issuer);
                wrong_type[field] = invalid;
                assert!(
                    discover_body(serde_json::to_vec(&wrong_type).unwrap(), &issuer)
                        .await
                        .is_err(),
                    "wrong type for {field}"
                );
            }
        }
    }

    #[tokio::test]
    async fn discovery_requires_the_expected_issuer() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        let mut document = discovery_document(&issuer);
        document["issuer"] = json!("https://login.example/realms/other");
        assert_eq!(
            discover_body(serde_json::to_vec(&document).unwrap(), &issuer)
                .await
                .err(),
            Some(Error::Protocol("discovered issuer mismatch"))
        );
    }

    #[tokio::test]
    async fn discovery_rejects_untrusted_endpoints() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        let endpoint_fields = [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "revocation_endpoint",
        ];
        let invalid_endpoints = [
            "/realms/test/relative",
            "http://login.example/realms/test/insecure",
            "https://attacker.example/endpoint",
            "https://login.example/endpoint#fragment",
            "https://user:secret@login.example/endpoint",
        ];
        for field in endpoint_fields {
            for endpoint in invalid_endpoints {
                let mut document = discovery_document(&issuer);
                document[field] = json!(endpoint);
                assert!(
                    discover_body(serde_json::to_vec(&document).unwrap(), &issuer)
                        .await
                        .is_err(),
                    "accepted {field}={endpoint}"
                );
            }
        }
    }

    #[tokio::test]
    async fn discovery_reports_endpoint_rejection_reason() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        let cases = [
            (
                "https://attacker.example/endpoint",
                "OIDC endpoint origin mismatch",
            ),
            (
                "https://user:secret@login.example/endpoint",
                "OIDC endpoint contains credentials",
            ),
            (
                "https://login.example/endpoint#fragment",
                "OIDC endpoint contains fragment",
            ),
        ];
        for (endpoint, expected) in cases {
            let mut document = discovery_document(&issuer);
            document["token_endpoint"] = json!(endpoint);
            assert_eq!(
                discover_body(serde_json::to_vec(&document).unwrap(), &issuer)
                    .await
                    .err(),
                Some(Error::Protocol(expected)),
                "{endpoint}"
            );
        }
    }

    #[tokio::test]
    async fn discovery_allows_extension_fields() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        let mut document = discovery_document(&issuer);
        document["vendor_extension"] = json!({"enabled": true});
        assert!(
            discover_body(serde_json::to_vec(&document).unwrap(), &issuer)
                .await
                .is_ok()
        );
    }

    #[test]
    fn multiple_audiences_require_authorized_party() {
        let claims = json!({"aud": ["himmelcloak", "other"]});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", "other"], "azp": "other"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", "other"], "azp": "himmelcloak"});
        assert!(audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", 7], "azp": "himmelcloak"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", null], "azp": "himmelcloak"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": "himmelcloak", "azp": "other"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": "himmelcloak", "azp": "himmelcloak"});
        assert!(audience_matches(&claims, "himmelcloak"));
    }

    #[test]
    fn rejects_invalid_id_token_claims() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = json!({
            "iss": "https://example.test/realms/test",
            "aud": "client",
            "sub": "alice",
            "exp": now + 3600,
            "iat": now,
            "nbf": now,
            "nonce": "request-nonce"
        });
        let verify = |claims: &serde_json::Value| {
            validate_claims(
                claims,
                "https://example.test/realms/test",
                "client",
                Some("request-nonce"),
            )
        };
        assert!(verify(&valid).is_ok());

        let cases = [
            (
                "iss",
                json!("https://other.example/realms/test"),
                "issuer mismatch",
            ),
            ("aud", json!("other-client"), "audience mismatch"),
            ("sub", json!(""), "missing subject"),
            ("exp", json!(now - 1), "token expired"),
            ("iat", json!(now + 120), "token issued in future"),
            ("nbf", json!(now + 120), "token not yet valid"),
            ("nonce", json!("wrong"), "nonce mismatch"),
        ];
        for (field, value, expected) in cases {
            let mut claims = valid.clone();
            claims[field] = value;
            assert_eq!(
                verify(&claims),
                Err(Error::TokenValidation(expected)),
                "{field}"
            );
        }
        let mut missing_subject = valid;
        missing_subject.as_object_mut().unwrap().remove("sub");
        assert_eq!(
            verify(&missing_subject),
            Err(Error::TokenValidation("missing subject"))
        );
    }

    #[test]
    fn rejects_malformed_jwt_before_key_lookup() {
        assert!(token_key_info("only.two").is_err());
        assert!(token_key_info(".claims.signature").is_err());
    }

    #[test]
    fn rs256_verification_fits_two_megabyte_thread_stack() {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let fixture: serde_json::Value =
                    serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json"))
                        .unwrap();
                let claims = verify_id_token(
                    fixture["token"].as_str().unwrap(),
                    &fixture["jwk"],
                    "https://example.test/realms/test",
                    "client",
                    None,
                )
                .unwrap();
                assert_eq!(claims["sub"], "alice");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn verifies_rs256_signature_and_rejects_tampering() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let token = fixture["token"].as_str().unwrap();
        let jwks = &fixture["jwk"];
        let verify = |value: &str| {
            verify_id_token(
                value,
                jwks,
                "https://example.test/realms/test",
                "client",
                None,
            )
        };
        assert_eq!(verify(token).unwrap()["sub"], "alice");

        let mut tampered = token.as_bytes().to_vec();
        let signature_start = tampered.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(verify(std::str::from_utf8(&tampered).unwrap()).is_err());

        let mut unknown_key = jwks.clone();
        unknown_key["keys"][0]["kid"] = json!("other");
        assert!(verify_id_token(
            token,
            &unknown_key,
            "https://example.test/realms/test",
            "client",
            None,
        )
        .is_err());
    }

    #[test]
    fn verifies_key_by_algorithm_when_key_ids_repeat() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let token = fixture["token"].as_str().unwrap();
        let valid = fixture["jwk"]["keys"][0].clone();
        let mut incompatible = valid.clone();
        incompatible["alg"] = json!("RS384");
        let kid = valid["kid"].as_str().unwrap();
        let incompatible_only = json!({"keys": [incompatible.clone()]});
        assert!(!jwks_has_eligible_key(&incompatible_only, kid, "RS256"));
        for jwks in [
            json!({"keys": [incompatible.clone(), valid.clone()]}),
            json!({"keys": [valid.clone(), incompatible.clone()]}),
        ] {
            assert!(jwks_has_eligible_key(&jwks, kid, "RS256"));
            assert_eq!(
                verify_id_token(
                    token,
                    &jwks,
                    "https://example.test/realms/test",
                    "client",
                    None,
                )
                .unwrap()["sub"],
                "alice"
            );
        }
    }

    #[test]
    fn verifies_es256_signature_and_rejects_wrong_curve() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/es256_id_token.json")).unwrap();
        let token = fixture["token"].as_str().unwrap();
        let jwks = &fixture["jwk"];
        assert_eq!(
            verify_id_token(
                token,
                jwks,
                "https://example.test/realms/test",
                "client",
                None,
            )
            .unwrap()["sub"],
            "alice"
        );

        let mut wrong_curve = jwks.clone();
        wrong_curve["keys"][0]["crv"] = json!("P-384");
        assert!(verify_id_token(
            token,
            &wrong_curve,
            "https://example.test/realms/test",
            "client",
            None,
        )
        .is_err());
    }
}
