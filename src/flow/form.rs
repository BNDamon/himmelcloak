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
//! Form extraction and submission: post a recognised page's form back to Keycloak.
//!
//! Every form goes to Keycloak's `login-actions/authenticate` address on the page's own site,
//! with the `session_code`, `execution`, `client_id`, and `tab_id` query values copied from the
//! page (charter section 2.6.4). Only the fields charter Table 2 lists for that page are posted:
//! `username`, `password`, `credentialId` on the login page; `otp`, `selectedCredentialId` on the
//! code page. Anything else is refused before a request is sent.
use core::fmt;

use url::Url;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::flow::classify::{PageKind, Scan};
use crate::flow::fetch::{self, CookieJar, Fetched, Page};
use crate::transport::HttpTransport;

const LOGIN_POSTED: &[&str] = &["username", "password", "credentialId"];
const OTP_POSTED: &[&str] = &["otp", "selectedCredentialId"];
const ACTION_PATH_SUFFIX: &str = "/login-actions/authenticate";
/// Query values Keycloak puts on every form action; each must appear exactly once.
const ACTION_QUERY: &[&str] = &["session_code", "execution", "client_id", "tab_id"];

/// A page's form, ready to be filled in and posted back.
pub(crate) struct Form {
    action: Url,
    /// The fields to post, in page order, with the values the page gave them.
    fields: Vec<(String, Zeroizing<String>)>,
    /// The OTP devices the page offers; a chosen `selectedCredentialId` must be one of them.
    devices: Vec<String>,
}

/// Classify `page` and extract its form. An unknown page, or a form that does not post to
/// Keycloak's own `login-actions/authenticate` address, is refused.
pub(crate) fn extract(page: &Page) -> Result<(PageKind, Form)> {
    let html =
        std::str::from_utf8(&page.body).map_err(|_| Error::Protocol("unknown login page"))?;
    let scan = Scan::run(html);
    // `kind()` returns `None` for every page it does not recognise, never `Some(Unknown)`.
    let kind = scan.kind().ok_or(Error::Protocol("unknown login page"))?;
    let (posted, mut devices) = if let PageKind::OneTimeCode { devices } = &kind {
        let ids = devices.iter().map(|device| device.id.clone()).collect();
        (OTP_POSTED, ids)
    } else {
        (LOGIN_POSTED, Vec::new())
    };
    if !scan
        .method
        .as_deref()
        .is_some_and(|method| method.eq_ignore_ascii_case("post"))
    {
        return Err(Error::Protocol("login form must use POST"));
    }
    let action = action_url(&page.url, scan.action.as_deref())?;
    let fields: Vec<(String, Zeroizing<String>)> = scan
        .controls
        .iter()
        // A browser submits a radio or checkbox only when it is selected.
        .filter(|control| {
            posted.contains(&control.name.as_str())
                && (!matches!(control.kind.as_str(), "radio" | "checkbox") || control.checked)
        })
        .map(|control| (control.name.clone(), Zeroizing::new(control.value.clone())))
        .collect();
    // With a single device the page offers no choice, but keycloak.v2 still posts that device's
    // ID in a hidden field; only that ID may be posted.
    if devices.is_empty() {
        devices = fields
            .iter()
            .filter(|(name, _)| name == "selectedCredentialId")
            .map(|(_, value)| value.to_string())
            .collect();
    }
    Ok((
        kind,
        Form {
            action,
            fields,
            devices,
        },
    ))
}

/// Resolve and check the form's `action`: HTTPS on the page's own site, Keycloak's
/// `login-actions/authenticate` path, and exactly one non-empty value for each of
/// `ACTION_QUERY`.
fn action_url(page: &Url, action: Option<&str>) -> Result<Url> {
    let action = action
        .filter(|action| !action.is_empty())
        .ok_or(Error::Protocol("login form without action"))?;
    let action = page
        .join(action)
        .map_err(|_| Error::Protocol("invalid login form action"))?;
    if action.scheme() != "https" || action.origin() != page.origin() {
        return Err(Error::Protocol("login form posts to another site"));
    }
    if !action.path().ends_with(ACTION_PATH_SUFFIX) {
        return Err(Error::Protocol("login form does not post to login-actions"));
    }
    let pairs: Vec<(String, String)> = action.query_pairs().into_owned().collect();
    for (i, (name, _)) in pairs.iter().enumerate() {
        if pairs[..i].iter().any(|(earlier, _)| earlier == name) {
            return Err(Error::Protocol("repeated login form action parameter"));
        }
    }
    for required in ACTION_QUERY {
        if !pairs
            .iter()
            .any(|(name, value)| name == required && !value.is_empty())
        {
            return Err(Error::Protocol("login form action missing session values"));
        }
    }
    Ok(action)
}

impl Form {
    /// Post the form with `answers` filled in. Each answer must name a field the page has, at
    /// most once, and a chosen device must be one the page offers; otherwise nothing is sent.
    pub(crate) async fn submit(
        &self,
        transport: &dyn HttpTransport,
        jar: &mut CookieJar,
        answers: &[(&str, &str)],
    ) -> Result<Fetched> {
        for (i, (name, value)) in answers.iter().enumerate() {
            if !self.fields.iter().any(|(field, _)| field == name) {
                return Err(Error::Protocol("answer for a field the page does not have"));
            }
            if answers[..i].iter().any(|(earlier, _)| earlier == name) {
                return Err(Error::Protocol("repeated answer"));
            }
            if *name == "selectedCredentialId" && !self.devices.iter().any(|device| device == value)
            {
                return Err(Error::Protocol("device not offered by the page"));
            }
        }
        let values: Vec<(&str, &str)> = self
            .fields
            .iter()
            .map(|(name, value)| {
                let answer = answers
                    .iter()
                    .find(|(answered, _)| answered == name)
                    .map(|(_, answer)| *answer);
                (name.as_str(), answer.unwrap_or(value.as_str()))
            })
            .collect();
        fetch::post_form(transport, jar, self.action.clone(), &values).await
    }
}

impl fmt::Debug for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The action's query carries the session code; field values can be secrets.
        let names: Vec<&str> = self.fields.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Form")
            .field(
                "action",
                &format_args!(
                    "{}{}",
                    self.action.origin().ascii_serialization(),
                    self.action.path()
                ),
            )
            .field("fields", &names)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use url::Url;

    use super::{extract, Form};
    use crate::error::{Error, Result};
    use crate::flow::classify::PageKind;
    use crate::flow::fetch::{CookieJar, Fetched, Page};
    use crate::transport::{HttpTransport, Request, Response};

    const BASE_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/base/login.html");
    const BASE_OTP: &str = include_str!("../../tests/fixtures/keycloak/base/login-otp.html");
    const BASE_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-otp-devices.html");
    const V2_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login.html");
    const V2_OTP: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp.html");
    const V2_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-devices.html");

    const PAGE_URL: &str =
        "https://keycloak.test:8443/realms/himmelcloak-test/protocol/openid-connect/auth";
    const ACTION: &str =
        "https://keycloak.test:8443/realms/himmelcloak-test/login-actions/authenticate";
    /// carol's devices in the fixtures (charter Table 23); bob's single device is the first.
    const DEVICE_1: &str = "00000000-0000-4000-8000-000000000001";
    const DEVICE_2: &str = "00000000-0000-4000-8000-000000000002";

    /// Each request's URL and decoded form body.
    type Sent = Vec<(Url, Vec<(String, String)>)>;

    /// Records each request and answers it with an empty page.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Sent>,
    }

    impl HttpTransport for Recorder {
        fn send(
            &self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let body = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            self.sent.lock().unwrap().push((request.url.clone(), body));
            Box::pin(async {
                Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: b"<html></html>".to_vec(),
                    cookies: Vec::new(),
                })
            })
        }
    }

    fn page(html: &str) -> Page {
        Page {
            url: Url::parse(PAGE_URL).unwrap(),
            status: 200,
            body: html.as_bytes().to_vec(),
        }
    }

    fn form(html: &str) -> Form {
        extract(&page(html)).unwrap().1
    }

    fn fields(form: &Form) -> Vec<(&str, &str)> {
        form.fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    /// Replace the page's form `action` attribute value.
    fn with_action(html: &str, action: &str) -> String {
        let start = html.find(r#"action=""#).unwrap() + r#"action=""#.len();
        let end = start + html[start..].find('"').unwrap();
        format!("{}{action}{}", &html[..start], &html[end..])
    }

    async fn submit(form: &Form, answers: &[(&str, &str)]) -> (Result<Fetched>, Recorder) {
        let recorder = Recorder::default();
        let mut jar = CookieJar::default();
        let result = form.submit(&recorder, &mut jar, answers).await;
        (result, recorder)
    }

    #[test]
    fn login_forms_keep_keycloak_session_values() {
        for html in [BASE_LOGIN, V2_LOGIN] {
            let (kind, form) = extract(&page(html)).unwrap();
            assert!(matches!(kind, PageKind::UsernamePassword));
            assert_eq!(form.action.as_str().split('?').next(), Some(ACTION));
            let query: Vec<(String, String)> = form.action.query_pairs().into_owned().collect();
            let expected = [
                ("session_code", "FIXTURE"),
                ("execution", "FIXTURE"),
                ("client_id", "himmelcloak-test-client"),
                ("tab_id", "FIXTURE"),
                ("client_data", "FIXTURE"),
            ];
            assert_eq!(query.len(), expected.len());
            for ((name, value), (want_name, want_value)) in query.iter().zip(expected) {
                assert_eq!((name.as_str(), value.as_str()), (want_name, want_value));
            }
            // Charter Table 2: the login page posts username, password, and credentialId.
            assert_eq!(
                fields(&form),
                [("username", ""), ("password", ""), ("credentialId", "")]
            );
        }
    }

    #[test]
    fn code_forms_keep_the_hidden_device_choice() {
        assert_eq!(fields(&form(BASE_OTP)), [("otp", "")]);
        assert_eq!(
            fields(&form(V2_OTP)),
            [("selectedCredentialId", DEVICE_1), ("otp", "")]
        );
        // base posts the checked radio; keycloak.v2 posts its hidden default.
        for html in [BASE_DEVICES, V2_DEVICES] {
            let (kind, form) = extract(&page(html)).unwrap();
            assert!(matches!(kind, PageKind::OneTimeCode { .. }));
            assert_eq!(
                fields(&form),
                [("selectedCredentialId", DEVICE_1), ("otp", "")]
            );
        }
    }

    #[tokio::test]
    async fn submission_posts_the_answers_to_the_page_action() {
        let login = form(BASE_LOGIN);
        let (result, recorder) = submit(
            &login,
            &[("username", "alice"), ("password", "synthetic-password")],
        )
        .await;
        assert!(matches!(result, Ok(Fetched::Page(_))));
        let sent = recorder.sent.into_inner().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, login.action);
        let body: Vec<(&str, &str)> = sent[0]
            .1
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            body,
            [
                ("username", "alice"),
                ("password", "synthetic-password"),
                ("credentialId", "")
            ]
        );
    }

    #[tokio::test]
    async fn submission_posts_the_chosen_or_default_device() {
        for (html, answers, device) in [
            (
                BASE_DEVICES,
                &[("otp", "123456"), ("selectedCredentialId", DEVICE_2)][..],
                DEVICE_2,
            ),
            (V2_DEVICES, &[("otp", "123456")][..], DEVICE_1),
            (
                V2_OTP,
                &[("otp", "123456"), ("selectedCredentialId", DEVICE_1)][..],
                DEVICE_1,
            ),
        ] {
            let (result, recorder) = submit(&form(html), answers).await;
            assert!(result.is_ok());
            let sent = recorder.sent.into_inner().unwrap();
            let body = &sent[0].1;
            assert_eq!(
                body,
                &[
                    ("selectedCredentialId".to_owned(), device.to_owned()),
                    ("otp".to_owned(), "123456".to_owned())
                ]
            );
        }
    }

    #[tokio::test]
    async fn bad_answers_are_refused_before_sending() {
        let other_device = "00000000-0000-4000-8000-000000000009";
        for (html, answers, reason) in [
            (
                BASE_LOGIN,
                &[("email", "x")][..],
                "answer for a field the page does not have",
            ),
            (
                BASE_LOGIN,
                &[("password", "a"), ("password", "b")][..],
                "repeated answer",
            ),
            (
                BASE_OTP,
                &[("selectedCredentialId", DEVICE_1)][..],
                "answer for a field the page does not have",
            ),
            (
                BASE_DEVICES,
                &[("selectedCredentialId", other_device)][..],
                "device not offered by the page",
            ),
            (
                V2_OTP,
                &[("selectedCredentialId", DEVICE_2)][..],
                "device not offered by the page",
            ),
        ] {
            let (result, recorder) = submit(&form(html), answers).await;
            assert_eq!(result.err(), Some(Error::Protocol(reason)), "{answers:?}");
            assert!(recorder.sent.into_inner().unwrap().is_empty());
        }
    }

    #[test]
    fn unknown_pages_and_non_post_forms_are_refused() {
        for (body, reason) in [
            (b"<html></html>".to_vec(), "unknown login page"),
            (vec![0xff, 0xfe], "unknown login page"),
            (
                BASE_LOGIN
                    .replace(r#"method="post""#, r#"method="get""#)
                    .into_bytes(),
                "login form must use POST",
            ),
            (
                BASE_LOGIN.replace(r#" method="post""#, "").into_bytes(),
                "login form must use POST",
            ),
        ] {
            let page = Page {
                url: Url::parse(PAGE_URL).unwrap(),
                status: 200,
                body,
            };
            assert_eq!(extract(&page).err(), Some(Error::Protocol(reason)));
        }
    }

    #[test]
    fn form_actions_must_be_keycloak_login_actions_on_the_same_site() {
        let path = "/realms/himmelcloak-test/login-actions/authenticate";
        let query = "session_code=a&amp;execution=b&amp;client_id=c&amp;tab_id=d";
        for (action, reason) in [
            (String::new(), "login form without action"),
            ("https://[::1".to_owned(), "invalid login form action"),
            (
                format!("https://evil.example{path}?{query}"),
                "login form posts to another site",
            ),
            (
                format!("http://keycloak.test:8443{path}?{query}"),
                "login form posts to another site",
            ),
            (
                format!("https://keycloak.test:8443/realms/himmelcloak-test/other?{query}"),
                "login form does not post to login-actions",
            ),
            (
                format!("{path}?execution=b&amp;client_id=c&amp;tab_id=d"),
                "login form action missing session values",
            ),
            (
                format!("{path}?session_code=a&amp;execution=b&amp;client_id=c&amp;tab_id="),
                "login form action missing session values",
            ),
            (
                format!("{path}?{query}&amp;execution=again"),
                "repeated login form action parameter",
            ),
        ] {
            let html = with_action(BASE_LOGIN, &action);
            assert_eq!(
                extract(&page(&html)).err(),
                Some(Error::Protocol(reason)),
                "{action}"
            );
        }
        // A relative action resolves against the page and stays on its site.
        let relative = form(&with_action(BASE_LOGIN, &format!("{path}?{query}")));
        assert_eq!(relative.action.as_str().split('?').next(), Some(ACTION));
    }

    #[test]
    fn debug_output_never_shows_session_values_or_answers() {
        assert_eq!(
            format!("{:?}", form(V2_DEVICES)),
            format!(r#"Form {{ action: {ACTION}, fields: ["selectedCredentialId", "otp"], .. }}"#)
        );
    }
}
