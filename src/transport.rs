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
use std::path::PathBuf;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use curl::easy::Easy;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_FORM: usize = 1024 * 1024;
const MAX_BLOCKING_REQUESTS: usize = 32;

#[derive(Clone, Copy)]
pub(crate) enum Method {
    Get,
    Post,
}

pub(crate) struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
    pub cookies: Vec<String>,
}

impl Request {
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::Get,
            url,
            headers: Vec::new(),
            body: Vec::new(),
            cookies: Vec::new(),
        }
    }

    pub fn form(url: Url, fields: &[(&str, &str)]) -> Result<Self> {
        // Each input byte can expand to three percent-encoded bytes. Reserve
        // the full upper bound before any secret is copied into the body.
        let capacity = fields
            .iter()
            .try_fold(0usize, |size, (name, value)| {
                name.len()
                    .checked_add(value.len())?
                    .checked_mul(3)?
                    .checked_add(2)?
                    .checked_add(size)
            })
            .filter(|size| *size <= MAX_FORM)
            .ok_or(Error::Protocol("form request too large"))?;
        let body = url::form_urlencoded::Serializer::new(String::with_capacity(capacity))
            .extend_pairs(fields.iter().copied())
            .finish()
            .into_bytes();
        Ok(Self {
            method: Method::Post,
            url,
            headers: vec!["Content-Type: application/x-www-form-urlencoded".to_owned()],
            body,
            cookies: Vec::new(),
        })
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        scrub_url(&mut self.url);
        self.body.zeroize();
        self.headers.zeroize();
        self.cookies.zeroize();
    }
}

/// Overwrite a URL's bytes before it is freed.
pub(crate) fn scrub_url(url: &mut Url) {
    if let Ok(blank) = Url::parse("data:,") {
        let mut text: String = std::mem::replace(url, blank).into();
        text.zeroize();
    }
}

pub(crate) struct Response {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub cookies: Vec<String>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
        for (name, value) in &mut self.headers {
            name.zeroize();
            value.zeroize();
        }
        self.cookies.zeroize();
    }
}

struct SecretHeaderList {
    head: *mut curl_sys::curl_slist,
    lengths: Vec<usize>,
}

impl SecretHeaderList {
    fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            lengths: Vec::new(),
        }
    }

    fn append(&mut self, header: &str) -> Result<()> {
        if header.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(Error::Protocol("invalid HTTP header"));
        }
        self.lengths
            .try_reserve(1)
            .map_err(|_| Error::Transport("HTTP header allocation failed".to_owned()))?;
        let capacity = header
            .len()
            .checked_add(1)
            .ok_or(Error::Protocol("invalid HTTP header"))?;
        let mut terminated = Zeroizing::new(Vec::with_capacity(capacity));
        terminated.extend_from_slice(header.as_bytes());
        terminated.push(0);
        // SAFETY: self.head is null or owned by this list, and terminated is
        // NUL-terminated and lives through the call. libcurl copies its bytes.
        let next = unsafe { curl_sys::curl_slist_append(self.head, terminated.as_ptr().cast()) };
        if next.is_null() {
            return Err(Error::Transport("HTTP header allocation failed".to_owned()));
        }
        self.head = next;
        self.lengths.push(header.len());
        Ok(())
    }

    fn install(&self, easy: &Easy) -> Result<()> {
        // SAFETY: easy.raw() is a live libcurl handle. self.head is null or
        // owns a valid list that outlives the handle and its transfer.
        let status = unsafe {
            curl_sys::curl_easy_setopt(easy.raw(), curl_sys::CURLOPT_HTTPHEADER, self.head)
        };
        if status == curl_sys::CURLE_OK {
            Ok(())
        } else {
            Err(Error::Transport(format!(
                "HTTP header setup failed: {status}"
            )))
        }
    }

    fn scrub(&mut self) {
        let mut node = self.head;
        for &length in &self.lengths {
            if node.is_null() {
                break;
            }
            // SAFETY: each node is owned by this list and remains allocated
            // until Drop finishes. lengths records each copied header's byte
            // length, excluding its NUL terminator. The Easy handle has been
            // dropped before this list is scrubbed in the production path.
            unsafe {
                if !(*node).data.is_null() {
                    std::slice::from_raw_parts_mut((*node).data.cast::<u8>(), length).zeroize();
                }
                node = (*node).next;
            }
        }
    }
}

impl Drop for SecretHeaderList {
    fn drop(&mut self) {
        self.scrub();
        // SAFETY: self.head is null or the list allocated by curl_slist_append;
        // no libcurl handle references it after the owning Easy is dropped.
        unsafe { curl_sys::curl_slist_free_all(self.head) };
    }
}

struct PendingJob {
    permit: Option<OwnedSemaphorePermit>,
    request: Option<Request>,
}

struct PendingTransfer {
    job: Arc<Mutex<PendingJob>>,
    abort: AbortHandle,
}

impl Drop for PendingTransfer {
    fn drop(&mut self) {
        // Tokio may leave an aborted spawn_blocking closure in its queue.
        // Remove its permit and request here, even if that queue is stalled.
        self.abort.abort();
        let (permit, request) = {
            let mut job = self
                .job
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (job.permit.take(), job.request.take())
        };
        drop(request);
        drop(permit);
    }
}

pub(crate) trait HttpTransport: Send + Sync {
    fn send(&self, request: Request)
        -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>>;
}

#[derive(Clone)]
pub(crate) struct CurlTransport {
    ca_bundle: Option<PathBuf>,
    timeout: Duration,
    slots: Arc<Semaphore>,
}

impl CurlTransport {
    pub fn new(ca_bundle: Option<PathBuf>, timeout: Duration) -> Result<Self> {
        curl::init();
        let backend = curl::Version::get()
            .ssl_version()
            .unwrap_or_default()
            .to_owned();
        if !active_wolfssl(&backend) {
            return Err(Error::TlsBackend);
        }
        static SHARED_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let slots = SHARED_SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(MAX_BLOCKING_REQUESTS)))
            .clone();
        Ok(Self {
            ca_bundle,
            timeout,
            slots,
        })
    }
}

fn active_wolfssl(version: &str) -> bool {
    // MultiSSL puts inactive backends in parentheses. Only the active entry
    // may satisfy the wolfSSL requirement.
    version
        .split_ascii_whitespace()
        .find(|backend| !backend.starts_with('('))
        .and_then(|backend| backend.split_once('/'))
        .is_some_and(|(name, release)| name.eq_ignore_ascii_case("wolfssl") && !release.is_empty())
}

impl HttpTransport for CurlTransport {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
        let ca_bundle = self.ca_bundle.clone();
        let timeout = self.timeout;
        let slots = self.slots.clone();
        Box::pin(async move {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| Error::Transport("Tokio runtime required".to_owned()))?;
            // Tokio panics when a runtime exists without its time driver.
            if std::panic::catch_unwind(|| tokio::time::sleep(Duration::ZERO)).is_err() {
                return Err(Error::Transport("Tokio time driver required".to_owned()));
            }
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or(Error::InvalidConfiguration("timeout too large"))?;
            let deadline_async = tokio::time::Instant::from_std(deadline);
            let permit = tokio::time::timeout_at(deadline_async, slots.acquire_owned())
                .await
                .map_err(|_| Error::Transport("HTTP request timed out".to_owned()))?
                .map_err(|_| Error::Transport("HTTP capacity unavailable".to_owned()))?;
            let job = Arc::new(Mutex::new(PendingJob {
                permit: Some(permit),
                request: Some(request),
            }));
            let worker_job = job.clone();
            let worker = runtime.spawn_blocking(move || {
                let (permit, request) = {
                    let mut job = worker_job
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    (job.permit.take(), job.request.take())
                };
                let Some((_permit, request)) = permit.zip(request) else {
                    return Err(Error::Transport("HTTP request timed out".to_owned()));
                };
                // A running libcurl transfer cannot be cancelled. Keep its
                // slot until the blocking transfer actually exits.
                let remaining = deadline.saturating_duration_since(Instant::now());
                let native_timeout = curl_timeout(remaining)
                    .ok_or(Error::Transport("HTTP request timed out".to_owned()))?;
                send_blocking(request, ca_bundle, native_timeout)
            });
            let _pending = PendingTransfer {
                job,
                abort: worker.abort_handle(),
            };
            tokio::time::timeout_at(deadline_async, worker)
                .await
                .map_err(|_| Error::Transport("HTTP request timed out".to_owned()))?
                .map_err(|_| Error::Transport("HTTP worker failed".to_owned()))?
        })
    }
}

fn curl_timeout(remaining: Duration) -> Option<Duration> {
    // libcurl uses millisecond precision; zero would disable its timeout.
    (!remaining.is_zero()).then(|| remaining.max(Duration::from_millis(1)))
}

fn send_blocking(
    request: Request,
    ca_bundle: Option<PathBuf>,
    timeout: Duration,
) -> Result<Response> {
    // Declare the list first so libcurl releases its handle before native
    // header copies are scrubbed and freed, including on early errors.
    let mut secret_headers = SecretHeaderList::new();
    let mut easy = Easy::new();
    easy.url(request.url.as_str()).map_err(curl_error)?;
    // Loopback HTTP is allowed for local tests; never send its credentials
    // through a proxy selected from the process environment.
    if request.url.scheme() == "http" {
        easy.proxy("").map_err(curl_error)?;
    }
    easy.timeout(timeout).map_err(curl_error)?;
    easy.connect_timeout(timeout).map_err(curl_error)?;
    easy.follow_location(false).map_err(curl_error)?;
    easy.ssl_verify_peer(true).map_err(curl_error)?;
    easy.ssl_verify_host(true).map_err(curl_error)?;
    easy.useragent(concat!("himmelcloak/", env!("CARGO_PKG_VERSION")))
        .map_err(curl_error)?;
    if let Some(path) = ca_bundle {
        easy.cainfo(path).map_err(curl_error)?;
    }
    easy.cookie_file("").map_err(curl_error)?;
    for cookie in &request.cookies {
        easy.cookie_list(cookie).map_err(curl_error)?;
    }
    if !request.headers.is_empty() {
        for header in &request.headers {
            secret_headers.append(header)?;
        }
        secret_headers.install(&easy)?;
    }
    if matches!(request.method, Method::Post) {
        easy.post(true).map_err(curl_error)?;
        easy.post_field_size(request.body.len() as u64)
            .map_err(curl_error)?;
    }

    let mut response = Response {
        status: 0,
        headers: Vec::new(),
        // Reserve the entire enforced bound so token bytes are never copied
        // into an old allocation that can be freed without zeroization.
        body: Vec::with_capacity(MAX_RESPONSE),
        cookies: Vec::new(),
    };
    let mut header_bytes = 0usize;
    let mut sent_bytes = 0usize;
    let oversized = std::cell::Cell::new(false);
    let transfer_result = {
        let mut transfer = easy.transfer();
        transfer
            .read_function(|buffer| {
                let remaining = &request.body[sent_bytes..];
                let count = remaining.len().min(buffer.len());
                buffer[..count].copy_from_slice(&remaining[..count]);
                sent_bytes += count;
                Ok(count)
            })
            .map_err(curl_error)?;
        transfer
            .write_function(|bytes| {
                if response.body.len().saturating_add(bytes.len()) > MAX_RESPONSE {
                    oversized.set(true);
                    return Ok(0);
                }
                response.body.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .map_err(curl_error)?;
        transfer
            .header_function(|line| {
                header_bytes = header_bytes.saturating_add(line.len());
                if header_bytes > MAX_HEADERS {
                    oversized.set(true);
                    return false;
                }
                if let Ok(line) = std::str::from_utf8(line) {
                    if let Some((name, value)) = line.split_once(':') {
                        response
                            .headers
                            .push((name.trim().to_owned(), value.trim().to_owned()));
                    }
                }
                true
            })
            .map_err(curl_error)?;
        transfer.perform()
    };
    if oversized.get() {
        return Err(Error::Protocol("HTTP response too large"));
    }
    transfer_result.map_err(curl_error)?;
    response.status = easy.response_code().map_err(curl_error)?;
    for cookie in easy.cookies().map_err(curl_error)?.iter() {
        let cookie =
            std::str::from_utf8(cookie).map_err(|_| Error::Protocol("invalid cookie encoding"))?;
        response.cookies.push(cookie.to_owned());
    }
    Ok(response)
}

fn curl_error(error: curl::Error) -> Error {
    Error::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{mpsc, Arc};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;

    use super::{
        active_wolfssl, curl_timeout, send_blocking, CurlTransport, HttpTransport, Request,
        SecretHeaderList, MAX_HEADERS, MAX_RESPONSE,
    };
    use crate::error::Error;
    use tokio::sync::Semaphore;
    use url::Url;

    struct NoopWake;

    #[test]
    fn positive_submillisecond_deadline_keeps_a_finite_native_timeout() {
        use std::time::Duration;

        assert_eq!(curl_timeout(Duration::ZERO), None);
        assert_eq!(
            curl_timeout(Duration::from_micros(500)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            curl_timeout(Duration::from_millis(2)),
            Some(Duration::from_millis(2))
        );
    }

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[test]
    fn missing_tokio_runtime_returns_an_error() {
        let transport = CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_secs(2),
            slots: Arc::new(Semaphore::new(1)),
        };
        let request = Request::get(Url::parse("http://127.0.0.1:9/").unwrap());
        let mut future = transport.send(request);
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::Transport(message))) if message == "Tokio runtime required"
        ));
    }

    #[test]
    fn runtime_without_timer_returns_an_error() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let transport = CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_secs(2),
            slots: Arc::new(Semaphore::new(1)),
        };
        let request = Request::get(Url::parse("http://127.0.0.1:9/").unwrap());
        assert_eq!(
            runtime.block_on(transport.send(request)).err(),
            Some(Error::Transport("Tokio time driver required".to_owned()))
        );
    }

    #[test]
    fn only_the_active_wolfssl_backend_is_accepted() {
        assert!(active_wolfssl("wolfSSL/5.9.4"));
        assert!(active_wolfssl("(OpenSSL/3.0.8) wolfSSL/5.9.4"));
        assert!(!active_wolfssl("OpenSSL/3.0.8 (wolfSSL/5.9.4)"));
        assert!(!active_wolfssl("(wolfSSL/5.9.4) OpenSSL/3.0.8"));
    }

    #[test]
    fn native_bearer_header_copy_is_scrubbed() {
        let bearer = "Authorization: Bearer synthetic-test-token";
        let mut headers = SecretHeaderList::new();
        headers.append(bearer).unwrap();
        // SAFETY: append succeeded, so head points to a live first node.
        let native = unsafe { (*headers.head).data.cast::<u8>() };
        // SAFETY: native points to libcurl's copy of bearer until headers drops.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(native, bearer.len()) },
            bearer.as_bytes()
        );
        headers.scrub();
        // SAFETY: scrub zeros the live allocation without freeing it.
        assert!(unsafe { std::slice::from_raw_parts(native, bearer.len()) }
            .iter()
            .all(|byte| *byte == 0));
        assert!(headers.append("Authorization: bad\r\nX-Evil: yes").is_err());
    }

    fn serve(header_size: usize, body_size: usize) -> (Url, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let thread = thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 || request.len() > 8192 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            let prefix = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_size}\r\nX-Pad: ");
            let suffix = "\r\n\r\n";
            let pad = "x".repeat(header_size - prefix.len() - suffix.len());
            let headers = format!("{prefix}{pad}{suffix}");
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&vec![b'x'; body_size]);
        });
        (url, thread)
    }

    fn accept_until(listener: &TcpListener) -> std::net::TcpStream {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("HTTP test accept failed: {error}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_request_holds_its_slot_until_libcurl_finishes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let (first_tx, first_rx) = mpsc::channel();
        let (second_tx, second_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut first = accept_until(&listener);
            first_tx.send(()).unwrap();
            let next_listener = listener.try_clone().unwrap();
            let second_server = thread::spawn(move || {
                let mut second = accept_until(&next_listener);
                second_tx.send(()).unwrap();
                second
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            });
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            drop(first);
            second_server.join().unwrap();
        });
        let transport = Arc::new(CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_secs(5),
            slots: Arc::new(Semaphore::new(1)),
        });
        let first_transport = transport.clone();
        let first_url = url.clone();
        let first =
            tokio::spawn(async move { first_transport.send(Request::get(first_url)).await });
        first_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        first.abort();
        let second = tokio::spawn(async move { transport.send(Request::get(url)).await });
        assert!(matches!(
            second_rx.recv_timeout(std::time::Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        assert_eq!(second.await.unwrap().unwrap().status, 200);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn request_timeout_includes_waiting_for_transport_capacity() {
        let slots = Arc::new(Semaphore::new(1));
        let occupied = slots.clone().acquire_owned().await.unwrap();
        let transport = CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_millis(100),
            slots,
        };
        let request = Request::get(Url::parse("http://127.0.0.1:9/").unwrap());
        let started = std::time::Instant::now();
        assert_eq!(
            transport.send(request).await.err(),
            Some(Error::Transport("HTTP request timed out".to_owned()))
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        drop(occupied);
    }

    #[test]
    fn timed_out_queued_worker_releases_its_slot() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let blocker = runtime.spawn_blocking(move || {
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        let slots = Arc::new(Semaphore::new(1));
        let transport = CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_millis(100),
            slots: slots.clone(),
        };
        let request = Request::get(Url::parse("http://127.0.0.1:9/").unwrap());
        assert_eq!(
            runtime.block_on(transport.send(request)).err(),
            Some(Error::Transport("HTTP request timed out".to_owned()))
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while slots.available_permits() == 0 && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(slots.available_permits(), 1);
        release_tx.send(()).unwrap();
        runtime.block_on(blocker).unwrap();
    }

    #[test]
    fn response_limits_accept_boundaries_and_reject_oversize() {
        for (header_size, body_size, allowed) in [
            (128, MAX_RESPONSE, true),
            (128, MAX_RESPONSE + 1, false),
            (MAX_HEADERS, 0, true),
            (MAX_HEADERS + 1, 0, false),
        ] {
            let (url, server) = serve(header_size, body_size);
            let response =
                send_blocking(Request::get(url), None, std::time::Duration::from_secs(5));
            server.join().unwrap();
            if allowed {
                let response = response.unwrap();
                assert_eq!(response.body.len(), body_size);
                assert!(response.body.capacity() >= MAX_RESPONSE);
            } else {
                assert!(matches!(
                    response,
                    Err(Error::Protocol("HTTP response too large"))
                ));
            }
        }
    }

    #[test]
    fn loopback_http_does_not_use_environment_proxy() {
        if std::env::var_os("HIMMELCLOAK_PROXY_TEST_CHILD").is_some() {
            let (url, server) = serve(128, 0);
            let response =
                send_blocking(Request::get(url), None, std::time::Duration::from_secs(5));
            server.join().unwrap();
            assert_eq!(response.unwrap().status, 200);
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transport::tests::loopback_http_does_not_use_environment_proxy",
            ])
            .env("HIMMELCLOAK_PROXY_TEST_CHILD", "1")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env_remove("no_proxy")
            .env_remove("NO_PROXY")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
