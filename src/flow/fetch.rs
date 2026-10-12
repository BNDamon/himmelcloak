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
//! Page fetching for the browser flow, with a cookie jar scoped to one login attempt.
//!
//! The transport starts every request with an empty libcurl cookie store. This module carries
//! cookies between requests: it loads the jar's lines for the request's exact origin, then
//! replaces that origin's lines with libcurl's cookie list from the response. Redirects are never
//! followed; they are returned so the flow driver decides every hop.
use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use url::{Host, Origin, Url};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::transport::{HttpTransport, Request};

/// Cookies for one login attempt, keyed by the exact origin (scheme, host, port) that set them.
///
/// Each cookie is a libcurl cookie line in Netscape format:
/// `domain \t subdomains \t path \t secure \t expiry \t name \t value`.
#[derive(Default)]
pub(crate) struct CookieJar {
    origins: Vec<(Origin, Vec<String>)>,
}

impl CookieJar {
    /// Lines to send with a request to `url`: only those its exact origin set.
    fn lines_for(&self, url: &Url) -> Vec<String> {
        self.lines_at(url, unix_now())
    }

    /// `lines_for` at a given time. Expiry is checked again here because a flow can sit paused
    /// between prompts long after the cookies arrived.
    fn lines_at(&self, url: &Url, now: u64) -> Vec<String> {
        let origin = url.origin();
        self.origins
            .iter()
            .filter(|(owner, _)| *owner == origin)
            .flat_map(|(_, lines)| lines)
            .filter(|line| unexpired(line, now))
            .cloned()
            .collect()
    }

    /// Replace the cookies of `url`'s origin with libcurl's list after a response.
    ///
    /// libcurl returns its whole store: the lines we sent, plus new or updated ones, minus any
    /// it deleted. Replacing instead of merging therefore applies server-side deletions too.
    fn replace(&mut self, url: &Url, lines: &[String]) {
        self.replace_at(url, lines, unix_now());
    }

    /// `replace` at a given time.
    fn replace_at(&mut self, url: &Url, lines: &[String], now: u64) {
        let Some(host) = url.host_str() else {
            return;
        };
        // libcurl writes IPv6 hosts without the URL's brackets.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let kept: Vec<String> = lines
            .iter()
            .filter(|line| usable(line, host, now))
            .cloned()
            .collect();
        let origin = url.origin();
        if let Some(index) = self.origins.iter().position(|(owner, _)| *owner == origin) {
            let (_, mut old) = self.origins.swap_remove(index);
            old.zeroize();
        }
        if !kept.is_empty() {
            self.origins.push((origin, kept));
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Test helper: store one Keycloak session cookie for `url`'s origin.
    #[cfg(test)]
    pub(crate) fn seed_session_cookie(&mut self, url: &Url) {
        let host = url.host_str().unwrap();
        self.replace(
            url,
            &[format!(
                "#HttpOnly_{host}\tFALSE\t/\tTRUE\t0\tAUTH_SESSION_ID\tsynthetic"
            )],
        );
    }

    /// Test helper: whether `url`'s origin holds a cookie named `name`.
    #[cfg(test)]
    fn contains(&self, url: &Url, name: &str) -> bool {
        self.lines_for(url)
            .iter()
            .any(|line| line.split('\t').nth(5) == Some(name))
    }
}

impl Drop for CookieJar {
    fn drop(&mut self) {
        for (_, lines) in &mut self.origins {
            lines.zeroize();
        }
    }
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Origins and counts only: cookie names and values never reach logs.
        f.write_str("CookieJar ")?;
        let mut map = f.debug_map();
        for (origin, lines) in &self.origins {
            map.entry(&origin.ascii_serialization(), &lines.len());
        }
        map.finish()
    }
}

/// Whether a libcurl cookie line is well formed, unexpired, and belongs to `host`.
fn usable(line: &str, host: &str, now: u64) -> bool {
    let fields: Vec<&str> = line.split('\t').collect();
    let [domain, _, _, _, _, name, _] = fields[..] else {
        return false;
    };
    let domain = domain.strip_prefix("#HttpOnly_").unwrap_or(domain);
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    !name.is_empty() && unexpired(line, now) && domain_matches(host, domain)
}

/// Whether a cookie line's expiry, in Unix seconds, has not passed at `now`.
fn unexpired(line: &str, now: u64) -> bool {
    // Expiry zero marks a session cookie; any other past time means it is no longer valid.
    line.split('\t')
        .nth(4)
        .and_then(|expiry| expiry.parse::<u64>().ok())
        .is_some_and(|expiry| expiry == 0 || expiry > now)
}

/// Whether `host` is `domain` or one of its subdomains, ignoring ASCII case.
fn domain_matches(host: &str, domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    let Some(split) = host.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    host.as_bytes()[split] == b'.'
        && host
            .get(split + 1..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(domain))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The result of one fetch. Redirects are reported, never followed.
#[derive(Debug)]
pub(crate) enum Fetched {
    Page(Page),
    Redirect(Redirect),
}

/// A non-redirect response, handed up for classification.
pub(crate) struct Page {
    pub url: Url,
    pub status: u32,
    pub body: Vec<u8>,
}

/// A 301, 302, 303, 307, or 308 response. The flow driver decides whether to go there.
pub(crate) struct Redirect {
    /// The `Location` header, resolved against the requested URL.
    pub location: Url,
    /// True when `location` has the requested URL's exact scheme, host, and port.
    pub same_origin: bool,
    /// Which redirect it was; decides how a next request would be made.
    pub kind: RedirectKind,
}

/// The redirect status codes `fetch` reports. Any other 3xx is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectKind {
    /// 301
    MovedPermanently,
    /// 302
    Found,
    /// 303
    SeeOther,
    /// 307
    TemporaryRedirect,
    /// 308
    PermanentRedirect,
}

impl RedirectKind {
    fn from_status(status: u32) -> Option<Self> {
        match status {
            301 => Some(Self::MovedPermanently),
            302 => Some(Self::Found),
            303 => Some(Self::SeeOther),
            307 => Some(Self::TemporaryRedirect),
            308 => Some(Self::PermanentRedirect),
            _ => None,
        }
    }

    /// True when a next request must repeat the original method and body (307, 308).
    /// After 301, 302, or 303 it continues as a GET without the form body, as browsers do.
    pub fn repeats_request(self) -> bool {
        matches!(self, Self::TemporaryRedirect | Self::PermanentRedirect)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        self.body.zeroize();
        scrub_url(&mut self.url);
    }
}

impl Drop for Redirect {
    fn drop(&mut self) {
        scrub_url(&mut self.location);
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("url", &Redacted(&self.url))
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl fmt::Debug for Redirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("location", &Redacted(&self.location))
            .field("same_origin", &self.same_origin)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Prints a URL without its query or fragment, which can carry session or authorization codes.
struct Redacted<'a>(&'a Url);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.0.origin().ascii_serialization(),
            self.0.path()
        )
    }
}

/// Overwrite a URL's bytes before it is freed.
fn scrub_url(url: &mut Url) {
    if let Ok(blank) = Url::parse("data:,") {
        let mut text: String = std::mem::replace(url, blank).into();
        text.zeroize();
    }
}

/// GET a page, sending only the cookies `url`'s origin set in this jar.
pub(crate) async fn get(
    transport: &dyn HttpTransport,
    jar: &mut CookieJar,
    url: Url,
) -> Result<Fetched> {
    send(transport, jar, Request::get(url)).await
}

/// POST a URL-encoded form, sending only the cookies `url`'s origin set in this jar.
pub(crate) async fn post_form(
    transport: &dyn HttpTransport,
    jar: &mut CookieJar,
    url: Url,
    fields: &[(&str, &str)],
) -> Result<Fetched> {
    send(transport, jar, Request::form(url, fields)?).await
}

/// HTTPS only, even on loopback (charter §2.6.8). Test builds also accept loopback HTTP so the
/// real-libcurl test can use a plain local server.
fn allowed_scheme(url: &Url) -> bool {
    url.scheme() == "https"
        || (cfg!(test)
            && url.scheme() == "http"
            && matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback()))
}

async fn send(
    transport: &dyn HttpTransport,
    jar: &mut CookieJar,
    mut request: Request,
) -> Result<Fetched> {
    if !allowed_scheme(&request.url) {
        return Err(Error::Protocol("page URL must use HTTPS"));
    }
    request.cookies = jar.lines_for(&request.url);
    let url = request.url.clone();
    let mut response = transport.send(request).await?;
    // Keep cookies from redirects too: Keycloak sets its session cookies on the 302 after login.
    jar.replace(&url, &response.cookies);
    if let Some(kind) = RedirectKind::from_status(response.status) {
        let location = response
            .header("Location")
            .ok_or(Error::Protocol("redirect without Location"))?;
        let location = url
            .join(location)
            .map_err(|_| Error::Protocol("invalid redirect Location"))?;
        let same_origin = location.origin() == url.origin();
        return Ok(Fetched::Redirect(Redirect {
            location,
            same_origin,
            kind,
        }));
    }
    match response.status {
        status @ 300..=399 => Err(Error::HttpStatus(status)),
        status => Ok(Fetched::Page(Page {
            url,
            status,
            // Move the buffer instead of copying it, so no unscrubbed copy of the page exists.
            body: std::mem::take(&mut response.body),
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    use url::Url;

    use super::{get, post_form, CookieJar, Fetched, Page, Redirect, RedirectKind};
    use crate::error::{Error, Result};
    use crate::flow::{AuthFlow, DEFAULT_LOGIN_TIMEOUT};
    use crate::transport::{CurlTransport, HttpTransport, Request, Response};

    const KC: &str = "https://keycloak.test:8443";

    /// One scripted server reply.
    struct Reply {
        status: u32,
        location: Option<&'static str>,
        set: Vec<String>,
    }

    /// Pretend server: plays scripted replies and records every request it receives.
    struct FakeTransport {
        script: Mutex<VecDeque<Reply>>,
        seen: Mutex<Vec<(Url, Vec<String>)>>,
    }

    impl FakeTransport {
        fn new(script: Vec<Reply>) -> Self {
            Self {
                script: Mutex::new(script.into()),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<(Url, Vec<String>)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl HttpTransport for FakeTransport {
        fn send(
            &self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            self.seen
                .lock()
                .unwrap()
                .push((request.url.clone(), request.cookies.clone()));
            let reply = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra request");
            // Imitate libcurl: return the cookies sent, with same-name ones replaced by this
            // reply's cookies.
            let mut cookies: Vec<String> = request
                .cookies
                .iter()
                .filter(|sent| reply.set.iter().all(|set| name(set) != name(sent)))
                .cloned()
                .collect();
            cookies.extend(reply.set.iter().cloned());
            let headers = reply
                .location
                .map(|location| vec![("Location".to_owned(), location.to_owned())])
                .unwrap_or_default();
            Box::pin(async move {
                Ok(Response {
                    status: reply.status,
                    headers,
                    body: b"<html></html>".to_vec(),
                    cookies,
                })
            })
        }
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn kc(path: &str) -> Url {
        url(&format!("{KC}{path}"))
    }

    fn page(set: Vec<String>) -> Reply {
        Reply {
            status: 200,
            location: None,
            set,
        }
    }

    fn redirect(location: &'static str, set: Vec<String>) -> Reply {
        Reply {
            status: 302,
            location: Some(location),
            set,
        }
    }

    /// A libcurl cookie line, as Keycloak's HttpOnly session cookies appear.
    fn line(domain: &str, name: &str, value: &str, expiry: u64) -> String {
        format!("#HttpOnly_{domain}\tFALSE\t/\tTRUE\t{expiry}\t{name}\t{value}")
    }

    fn cookie(name: &str, value: &str) -> String {
        line("keycloak.test", name, value, 0)
    }

    fn name(line: &str) -> &str {
        line.split('\t').nth(5).unwrap()
    }

    fn values(lines: &[String]) -> Vec<&str> {
        lines
            .iter()
            .map(|line| line.rsplit('\t').next().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn two_logins_never_share_cookies() {
        let transport = FakeTransport::new(vec![
            page(vec![cookie("AUTH_SESSION_ID", "synthetic-alice")]),
            page(vec![cookie("AUTH_SESSION_ID", "synthetic-bob")]),
            page(vec![]),
            page(vec![]),
        ]);
        let login = kc("/realms/test/protocol/openid-connect/auth");
        let mut alice = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT);
        let mut bob = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT);
        get(&transport, &mut alice.jar, login.clone())
            .await
            .unwrap();
        get(&transport, &mut bob.jar, login.clone()).await.unwrap();
        get(&transport, &mut alice.jar, login.clone())
            .await
            .unwrap();
        get(&transport, &mut bob.jar, login).await.unwrap();

        let seen = transport.seen();
        assert!(seen[0].1.is_empty());
        assert!(
            seen[1].1.is_empty(),
            "a new login must not inherit another login's cookies"
        );
        assert_eq!(values(&seen[2].1), ["synthetic-alice"]);
        assert_eq!(values(&seen[3].1), ["synthetic-bob"]);
    }

    #[tokio::test]
    async fn redirect_to_another_host_is_surfaced_not_followed() {
        let transport = FakeTransport::new(vec![
            page(vec![cookie("AUTH_SESSION_ID", "synthetic-session")]),
            redirect(
                "https://evil.example/steal",
                vec![cookie("KEYCLOAK_IDENTITY", "synthetic-identity")],
            ),
        ]);
        let mut jar = CookieJar::default();
        get(&transport, &mut jar, kc("/realms/test/login"))
            .await
            .unwrap();
        let fetched = post_form(
            &transport,
            &mut jar,
            kc("/realms/test/login-actions/authenticate"),
            &[("password", "synthetic-password")],
        )
        .await
        .unwrap();

        let Fetched::Redirect(redirect) = fetched else {
            panic!("expected a redirect");
        };
        assert_eq!(redirect.location.as_str(), "https://evil.example/steal");
        assert!(!redirect.same_origin);
        let seen = transport.seen();
        assert_eq!(seen.len(), 2, "the redirect must not be followed");
        assert!(seen
            .iter()
            .all(|(sent_to, _)| sent_to.host_str() == Some("keycloak.test")));
        assert!(jar.lines_for(&redirect.location).is_empty());
        assert!(
            jar.contains(&url(KC), "KEYCLOAK_IDENTITY"),
            "cookies set on a redirect are kept"
        );
    }

    #[tokio::test]
    async fn same_origin_redirect_is_resolved_flagged_and_not_followed() {
        let transport = FakeTransport::new(vec![redirect(
            "/realms/test/login-actions/required-action?execution=synthetic",
            vec![],
        )]);
        let mut jar = CookieJar::default();
        let fetched = get(
            &transport,
            &mut jar,
            kc("/realms/test/login-actions/authenticate"),
        )
        .await
        .unwrap();

        let Fetched::Redirect(redirect) = fetched else {
            panic!("expected a redirect");
        };
        assert_eq!(
            redirect.location,
            kc("/realms/test/login-actions/required-action?execution=synthetic")
        );
        assert!(redirect.same_origin);
        assert_eq!(transport.seen().len(), 1);
    }

    #[tokio::test]
    async fn post_redirects_report_whether_the_request_must_be_repeated() {
        for (status, kind, repeats) in [
            (303, RedirectKind::SeeOther, false),
            (307, RedirectKind::TemporaryRedirect, true),
            (308, RedirectKind::PermanentRedirect, true),
        ] {
            let transport = FakeTransport::new(vec![Reply {
                status,
                location: Some("/realms/test/login-actions/authenticate?execution=next"),
                set: vec![],
            }]);
            let mut jar = CookieJar::default();
            let fetched = post_form(
                &transport,
                &mut jar,
                kc("/realms/test/login-actions/authenticate"),
                &[("password", "synthetic-password")],
            )
            .await
            .unwrap();

            let Fetched::Redirect(redirect) = fetched else {
                panic!("expected a redirect for {status}");
            };
            assert_eq!(redirect.kind, kind);
            assert_eq!(redirect.kind.repeats_request(), repeats);
            assert_eq!(transport.seen().len(), 1, "{status} must not be followed");
        }
    }

    #[tokio::test]
    async fn cookies_are_only_sent_to_their_exact_origin() {
        let transport = FakeTransport::new(vec![
            page(vec![cookie("AUTH_SESSION_ID", "synthetic-session")]),
            page(vec![]),
            page(vec![]),
            page(vec![]),
        ]);
        let mut jar = CookieJar::default();
        // Plain http to the same host is refused outright: see the HTTPS test below.
        for target in [
            KC,
            "https://keycloak.test:9443",
            "https://other.test:8443",
            KC,
        ] {
            get(&transport, &mut jar, url(target)).await.unwrap();
        }

        let seen = transport.seen();
        for (other_origin, cookies) in &seen[1..3] {
            assert!(cookies.is_empty(), "cookie leaked to {other_origin}");
        }
        assert_eq!(values(&seen[3].1), ["synthetic-session"]);
    }

    #[tokio::test]
    async fn server_deleted_cookies_stop_being_sent() {
        let transport = FakeTransport::new(vec![
            page(vec![cookie("KC_RESTART", "synthetic-restart")]),
            // Max-Age=0 reaches the jar as a line with an expiry in the past.
            page(vec![line("keycloak.test", "KC_RESTART", "", 1)]),
            page(vec![]),
        ]);
        let mut jar = CookieJar::default();
        for _ in 0..3 {
            get(&transport, &mut jar, url(KC)).await.unwrap();
        }

        let seen = transport.seen();
        assert_eq!(values(&seen[1].1), ["synthetic-restart"]);
        assert!(seen[2].1.is_empty());
        assert!(!jar.contains(&url(KC), "KC_RESTART"));
    }

    #[test]
    fn cookies_expire_while_a_login_waits() {
        let mut jar = CookieJar::default();
        jar.replace_at(
            &url(KC),
            &[line(
                "keycloak.test",
                "KC_RESTART",
                "synthetic-restart",
                1_000,
            )],
            900,
        );
        // No response arrives in between: the flow is paused waiting for the user.
        assert_eq!(values(&jar.lines_at(&url(KC), 999)), ["synthetic-restart"]);
        assert!(jar.lines_at(&url(KC), 1_000).is_empty());
    }

    #[test]
    fn malformed_and_foreign_domain_lines_are_dropped() {
        let mut jar = CookieJar::default();
        jar.replace(
            &url(KC),
            &[
                "not a cookie line".to_owned(),
                line("other.test", "FOREIGN", "synthetic", 0),
                line("cloak.test", "LOOKALIKE", "synthetic", 0),
                line(".keycloak.test", "DOMAIN_WIDE", "synthetic", 0),
            ],
        );
        assert!(!jar.contains(&url(KC), "FOREIGN"));
        assert!(!jar.contains(&url(KC), "LOOKALIKE"));
        assert!(jar.contains(&url(KC), "DOMAIN_WIDE"));
        assert_eq!(jar.lines_for(&url(KC)).len(), 1);
    }

    #[test]
    fn debug_output_never_shows_cookies_codes_or_page_bodies() {
        let mut jar = CookieJar::default();
        jar.replace(&url(KC), &[cookie("AUTH_SESSION_ID", "synthetic-secret")]);
        assert_eq!(
            format!("{jar:?}"),
            "CookieJar {\"https://keycloak.test:8443\": 1}"
        );

        let page = Fetched::Page(Page {
            url: kc("/realms/test/login?session_code=synthetic-code"),
            status: 200,
            body: b"synthetic-body".to_vec(),
        });
        let redirect = Fetched::Redirect(Redirect {
            location: url("http://127.0.0.1:8845/callback?code=synthetic-code"),
            same_origin: false,
            kind: RedirectKind::Found,
        });
        for text in [format!("{page:?}"), format!("{redirect:?}")] {
            assert!(!text.contains("synthetic"), "secret in {text}");
        }
    }

    #[tokio::test]
    async fn redirect_without_location_is_a_protocol_error() {
        let transport = FakeTransport::new(vec![Reply {
            status: 302,
            location: None,
            set: vec![],
        }]);
        let mut jar = CookieJar::default();
        assert_eq!(
            get(&transport, &mut jar, url(KC)).await.err(),
            Some(Error::Protocol("redirect without Location"))
        );
    }

    #[tokio::test]
    async fn only_https_urls_are_fetched() {
        let transport = FakeTransport::new(vec![]);
        let mut jar = CookieJar::default();
        jar.replace(&url(KC), &[cookie("AUTH_SESSION_ID", "synthetic-session")]);
        for target in [
            "http://keycloak.test:8443/realms/test/login",
            "ftp://keycloak.test/",
        ] {
            assert_eq!(
                get(&transport, &mut jar, url(target)).await.err(),
                Some(Error::Protocol("page URL must use HTTPS")),
                "{target} must be refused"
            );
        }
        assert!(
            transport.seen().is_empty(),
            "nothing may be sent before the check"
        );
    }

    fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut buffer = [0u8; 1024];
        while !head.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            head.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(head).unwrap()
    }

    /// Proves the jar understands real libcurl cookie lines, not only the fake's imitation.
    #[tokio::test]
    async fn real_libcurl_cookies_round_trip_and_expire() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = url(&format!("http://{}/", listener.local_addr().unwrap()));
        let replies = [
            "Set-Cookie: AUTH_SESSION_ID=synthetic-session; Path=/; HttpOnly\r\n",
            "",
            "Set-Cookie: AUTH_SESSION_ID=; Max-Age=0; Path=/\r\n",
            "",
        ];
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for set_cookie in replies {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_head(&mut stream));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\n{set_cookie}Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
            requests
        });
        let transport = CurlTransport::new(None, Duration::from_secs(5)).unwrap();
        let mut jar = CookieJar::default();
        for _ in 0..4 {
            get(&transport, &mut jar, base.clone()).await.unwrap();
        }

        let requests = server.join().unwrap();
        let cookie_header = |request: &str| {
            request
                .lines()
                .find(|header| header.to_ascii_lowercase().starts_with("cookie:"))
                .map(str::to_owned)
        };
        assert_eq!(cookie_header(&requests[0]), None);
        for request in &requests[1..3] {
            assert_eq!(
                cookie_header(request).as_deref(),
                Some("Cookie: AUTH_SESSION_ID=synthetic-session")
            );
        }
        assert_eq!(cookie_header(&requests[3]), None);
    }
}
