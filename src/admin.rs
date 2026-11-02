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
//! Read-only Keycloak group membership retrieval for the NSS sync job.
//! No endpoint for listing all users, group discovery, or mutation is exposed.
use crate::{
    config::Config,
    error::{Error, Result},
    standard,
    transport::{CurlTransport, HttpTransport, Request},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

const PAGE_SIZE: usize = 100;
const MAX_MEMBERS: usize = 100_000;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GroupMember {
    pub id: String,
    pub username: String,
    pub enabled: bool,
}

/// Obtain a client-credentials token and read only the configured group's members.
/// The service account must have read-only group/member access, never manage-users.
/// Returns no partial results if any request, authorization or response check fails.
pub async fn read_allowed_group(
    config: &Config,
    group_id: &str,
    client_secret: &str,
) -> Result<Vec<GroupMember>> {
    validate(config, group_id, client_secret)?;
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout)?;
    read_with_transport(config, group_id, client_secret, &transport).await
}

fn validate(config: &Config, group_id: &str, secret: &str) -> Result<()> {
    config.validate()?;
    if group_id.is_empty()
        || matches!(group_id, "." | "..")
        || group_id
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(Error::InvalidConfiguration("allowed group ID"));
    }
    if secret.is_empty() {
        return Err(Error::InvalidConfiguration("service account secret"));
    }
    Ok(())
}

fn endpoint(config: &Config, segments: &[&str]) -> Result<Url> {
    let mut url = config.server_url.clone();
    url.path_segments_mut()
        .map_err(|_| Error::InvalidConfiguration("server URL"))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

async fn read_with_transport(
    config: &Config,
    group_id: &str,
    secret: &str,
    transport: &dyn HttpTransport,
) -> Result<Vec<GroupMember>> {
    validate(config, group_id, secret)?;
    let token_url = endpoint(
        config,
        &[
            "realms",
            &config.realm,
            "protocol",
            "openid-connect",
            "token",
        ],
    )?;
    let tokens = standard::acquire(
        transport,
        token_url,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &config.client_id),
            ("client_secret", secret),
        ],
        false,
    )
    .await?;
    if !tokens.access_token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Protocol("invalid service account token"));
    }
    let base = endpoint(
        config,
        &[
            "admin",
            "realms",
            &config.realm,
            "groups",
            group_id,
            "members",
        ],
    )?;
    let mut members = Vec::new();
    let mut seen = HashSet::new();
    loop {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("first", &members.len().to_string())
            .append_pair("max", &PAGE_SIZE.to_string())
            .append_pair("briefRepresentation", "true");
        let mut request = Request::get(url);
        request
            .headers
            .push(format!("Authorization: Bearer {}", tokens.access_token));
        request.headers.push("Accept: application/json".into());
        let response = transport.send(request).await?;
        if response.status != 200 {
            return Err(Error::HttpStatus(response.status));
        }
        let page: Vec<GroupMember> = serde_json::from_slice(&response.body)
            .map_err(|_| Error::Protocol("invalid group member response"))?;
        if page.len() > PAGE_SIZE || members.len() + page.len() > MAX_MEMBERS {
            return Err(Error::Protocol("group member limit exceeded"));
        }
        if page.is_empty() {
            return Ok(members);
        }
        for member in page {
            if member.id.is_empty()
                || member.username.trim().is_empty()
                || !seen.insert(member.id.clone())
            {
                return Err(Error::Protocol("invalid or repeated group member"));
            }
            members.push(member);
        }
        // Continue until an empty page, even if the server applies a lower page-size cap.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Method, Response};
    use std::{collections::VecDeque, future::Future, pin::Pin, sync::Mutex};

    type RecordedRequest = (bool, String, String, Vec<String>);

    struct Fake {
        responses: Mutex<VecDeque<(u32, String)>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }
    impl Fake {
        fn new(responses: Vec<(u32, &str)>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(|(s, b)| (s, b.into())).collect()),
                requests: Mutex::new(vec![]),
            }
        }
    }
    impl HttpTransport for Fake {
        fn send(
            &self,
            req: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            self.requests.lock().unwrap().push((
                matches!(req.method, Method::Post),
                req.url.to_string(),
                String::from_utf8(req.body.clone()).unwrap(),
                req.headers.clone(),
            ));
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected HTTP request");
            Box::pin(async move {
                Ok(Response {
                    status,
                    body: body.into_bytes(),
                    headers: vec![],
                    cookies: vec![],
                })
            })
        }
    }
    const TOKEN: &str = r#"{"access_token":"test-token","token_type":"Bearer"}"#;
    const ALICE: &str = r#"[{"id":"a","username":"alice","enabled":true}]"#;
    fn config() -> Config {
        Config::new("https://keycloak.example/auth", "test", "sync").unwrap()
    }

    #[tokio::test]
    async fn paginates_only_the_configured_group_never_all_users() {
        let fake = Fake::new(vec![
            (200, TOKEN),
            (200, ALICE),
            (200, r#"[{"id":"b","username":"bob","enabled":false}]"#),
            (200, "[]"),
        ]);
        let members = read_with_transport(&config(), "allowed-group", "secret", &fake)
            .await
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(!members[1].enabled);
        let reqs = fake.requests.lock().unwrap();
        assert!(reqs[0].0);
        assert_eq!(
            reqs[0].1,
            "https://keycloak.example/auth/realms/test/protocol/openid-connect/token"
        );
        let fields: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(reqs[0].2.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(fields["grant_type"], "client_credentials");
        assert_eq!(fields["client_id"], "sync");
        assert_eq!(fields["client_secret"], "secret");
        for (index, req) in reqs[1..].iter().enumerate() {
            assert!(!req.0);
            let url = Url::parse(&req.1).unwrap();
            assert_eq!(
                url.path(),
                "/auth/admin/realms/test/groups/allowed-group/members"
            );
            let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(query["first"], index.to_string());
            assert_eq!(query["max"], "100");
            assert!(req
                .3
                .contains(&"Authorization: Bearer test-token".to_owned()));
        }
        assert_eq!(reqs.len(), 4);
    }

    #[tokio::test]
    async fn full_page_advances_by_page_size_and_oversized_page_is_rejected() {
        let users: Vec<_>=(0..=PAGE_SIZE).map(|i| serde_json::json!({"id":i.to_string(),"username":format!("user{i}"),"enabled":true})).collect();
        let full = serde_json::to_string(&users[..PAGE_SIZE]).unwrap();
        let fake = Fake::new(vec![(200, TOKEN), (200, &full), (200, "[]")]);
        assert_eq!(
            read_with_transport(&config(), "allowed", "secret", &fake)
                .await
                .unwrap()
                .len(),
            PAGE_SIZE
        );
        assert!(fake.requests.lock().unwrap()[2]
            .1
            .contains("first=100&max=100"));
        let oversized = serde_json::to_string(&users).unwrap();
        let fake = Fake::new(vec![(200, TOKEN), (200, &oversized)]);
        assert!(read_with_transport(&config(), "allowed", "secret", &fake)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn empty_group_returns_no_members() {
        let fake = Fake::new(vec![(200, TOKEN), (200, "[]")]);
        assert!(read_with_transport(&config(), "empty", "secret", &fake)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(fake.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn auth_failure_never_queries_members() {
        let fake = Fake::new(vec![(401, r#"{"error":"invalid_client"}"#)]);
        assert!(read_with_transport(&config(), "allowed", "secret", &fake)
            .await
            .is_err());
        assert_eq!(fake.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failures_never_fall_back_to_all_users_or_return_partial_results() {
        for status in [401, 403, 404, 429, 500] {
            let fake = Fake::new(vec![(200, TOKEN), (200, ALICE), (status, "failure")]);
            assert_eq!(
                read_with_transport(&config(), "allowed", "secret", &fake).await,
                Err(Error::HttpStatus(status))
            );
            assert_eq!(fake.requests.lock().unwrap().len(), 3);
        }
    }

    #[tokio::test]
    async fn rejects_bad_or_repeating_pages() {
        for body in ["not json", "{}", r#"[{"id":"a","enabled":true}]"#, ALICE] {
            let fake = Fake::new(vec![(200, TOKEN), (200, ALICE), (200, body)]);
            assert!(read_with_transport(&config(), "allowed", "secret", &fake)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn rejects_invalid_group_before_any_http_request() {
        for group in ["", ".", "..", "a/b", "a\\b", "a\n"] {
            let fake = Fake::new(vec![]);
            assert!(read_with_transport(&config(), group, "secret", &fake)
                .await
                .is_err());
            assert!(fake.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn rejects_empty_secret_and_invalid_configuration_before_http() {
        let fake = Fake::new(vec![]);
        assert!(read_with_transport(&config(), "allowed", "", &fake)
            .await
            .is_err());
        let mut invalid = config();
        invalid.server_url = Url::parse("http://keycloak.example").unwrap();
        assert!(read_allowed_group(&invalid, "allowed", "secret")
            .await
            .is_err());
        assert!(fake.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn group_id_cannot_change_the_endpoint_or_query() {
        let fake = Fake::new(vec![(200, TOKEN), (200, "[]")]);
        read_with_transport(&config(), "group?x=#value", "secret", &fake)
            .await
            .unwrap();
        let reqs = fake.requests.lock().unwrap();
        let url = Url::parse(&reqs[1].1).unwrap();
        assert!(url.path().ends_with("/groups/group%3Fx=%23value/members"));
        assert!(url.fragment().is_none());
        assert_eq!(url.query_pairs().count(), 3);
    }

    #[tokio::test]
    async fn token_header_injection_is_rejected() {
        let fake = Fake::new(vec![(
            200,
            r#"{"access_token":"bad\r\nheader","token_type":"Bearer"}"#,
        )]);
        assert!(read_with_transport(&config(), "allowed", "secret", &fake)
            .await
            .is_err());
        assert_eq!(fake.requests.lock().unwrap().len(), 1);
    }
    /// Uses the disposable group-sync realm; no production server or credentials.
    #[tokio::test]
    #[ignore = "requires the disposable HTTPS Keycloak HC-49 fixture"]
    async fn read_only_service_account_live() {
        let server = std::env::var("HC49_KEYCLOAK_URL")
            .or_else(|_| std::env::var("KEYCLOAK_URL"))
            .expect("HC49_KEYCLOAK_URL or KEYCLOAK_URL");
        let ca = std::env::var("HC49_KEYCLOAK_CA")
            .or_else(|_| std::env::var("KEYCLOAK_CA"))
            .expect("HC49_KEYCLOAK_CA or KEYCLOAK_CA");
        let mut config = Config::new(&server, "hc49-test", "hc49-sync").unwrap();
        config.ca_bundle = Some(ca.into());
        let group = "11111111-1111-4111-8111-111111111111";
        let members = read_allowed_group(&config, group, "hc49-disposable-test-secret")
            .await
            .unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].username, "allowed-alice");
        assert!(members.iter().all(|m| m.username != "outside-bob"));
        // Verify the same service account cannot create users (read-only access).
        let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();
        let token = standard::acquire(
            &transport,
            endpoint(
                &config,
                &[
                    "realms",
                    &config.realm,
                    "protocol",
                    "openid-connect",
                    "token",
                ],
            )
            .unwrap(),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "hc49-sync"),
                ("client_secret", "hc49-disposable-test-secret"),
            ],
            false,
        )
        .await
        .unwrap();
        let mut request =
            Request::get(endpoint(&config, &["admin", "realms", &config.realm, "users"]).unwrap());
        request.method = Method::Post;
        request.headers = vec![
            format!("Authorization: Bearer {}", token.access_token),
            "Content-Type: application/json".into(),
        ];
        request.body = br#"{"username":"must-not-be-created","enabled":true}"#.to_vec();
        assert_eq!(transport.send(request).await.unwrap().status, 403);
        config.client_id = "hc49-no-permission".into();
        assert_eq!(
            read_allowed_group(&config, group, "hc49-disposable-denied-secret").await,
            Err(Error::HttpStatus(403))
        );
    }
}
