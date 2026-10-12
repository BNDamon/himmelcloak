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
use std::time::Duration;

use url::Url;

use crate::error::{Error, Result};

/// Runtime settings for a public Keycloak client.
#[non_exhaustive]
#[derive(Clone)]
pub struct Config {
    pub server_url: Url,
    pub realm: String,
    pub client_id: String,
    pub redirect_uri: Url,
    pub ca_bundle: Option<PathBuf>,
    pub timeout: Duration,
}

impl Config {
    pub fn new(server_url: &str, realm: &str, client_id: &str) -> Result<Self> {
        let server_url =
            Url::parse(server_url).map_err(|_| Error::InvalidConfiguration("server URL"))?;
        let config = Self {
            server_url,
            realm: realm.to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri: Url::parse("http://127.0.0.1:8845/himmelcloak/callback")
                .expect("constant URL"),
            ca_bundle: None,
            timeout: Duration::from_secs(15),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.server_url.scheme() != "https" {
            return Err(Error::InvalidConfiguration(
                "Keycloak issuer requires HTTPS",
            ));
        }
        if self.server_url.query().is_some()
            || self.server_url.fragment().is_some()
            || !self.server_url.username().is_empty()
            || self.server_url.password().is_some()
        {
            return Err(Error::InvalidConfiguration(
                "server URL must not have credentials, query, or fragment",
            ));
        }
        // The callback is matched by scheme, host, port, and path only, so a fixed query
        // (RFC 6749 section 3.1.2) could not be verified; refuse one rather than ignore it.
        if self.redirect_uri.query().is_some() || self.redirect_uri.fragment().is_some() {
            return Err(Error::InvalidConfiguration(
                "redirect URI must not have a query or fragment",
            ));
        }
        if self.realm.is_empty()
            || self.realm.contains('/')
            || matches!(self.realm.as_str(), "." | "..")
            || self.client_id.is_empty()
        {
            return Err(Error::InvalidConfiguration("realm or client ID"));
        }
        if self.timeout < Duration::from_millis(1) {
            return Err(Error::InvalidConfiguration(
                "timeout must be at least one millisecond",
            ));
        }
        Ok(())
    }

    pub(crate) fn issuer(&self) -> Result<Url> {
        let mut url = self.server_url.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidConfiguration("server URL cannot be a base"))?
            .pop_if_empty()
            .push("realms")
            .push(&self.realm);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use url::Url;

    #[test]
    fn rejects_credentials_embedded_in_server_url() {
        assert!(Config::new("https://user:secret@keycloak.example", "test", "client").is_err());
    }

    #[test]
    fn revalidates_public_config_fields_before_use() {
        let mut config = Config::new("https://keycloak.example", "test", "client").unwrap();
        config.server_url = Url::parse("http://remote.example").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn requires_https_even_for_loopback_issuer() {
        assert!(Config::new("https://[::1]:8443", "test", "client").is_ok());
        for url in [
            "http://127.0.0.1:8443",
            "http://[::1]:8443",
            "http://keycloak.example",
        ] {
            assert!(Config::new(url, "test", "client").is_err());
        }
    }

    #[test]
    fn rejects_redirect_uris_with_a_query_or_fragment() {
        for redirect in [
            "http://127.0.0.1:8845/himmelcloak/callback?tenant=a",
            "http://127.0.0.1:8845/himmelcloak/callback#done",
        ] {
            let mut config = Config::new("https://keycloak.example", "test", "client").unwrap();
            config.redirect_uri = Url::parse(redirect).unwrap();
            assert!(config.validate().is_err(), "{redirect}");
        }
    }

    #[test]
    fn rejects_dot_segment_realms() {
        for realm in [".", ".."] {
            assert!(Config::new("https://keycloak.example", realm, "client").is_err());
        }
    }

    #[test]
    fn rejects_timeouts_below_libcurl_resolution() {
        for timeout in [
            std::time::Duration::ZERO,
            std::time::Duration::from_micros(500),
        ] {
            let mut config = Config::new("https://keycloak.example", "test", "client").unwrap();
            config.timeout = timeout;
            assert!(config.validate().is_err());
        }
        let mut config = Config::new("https://keycloak.example", "test", "client").unwrap();
        config.timeout = std::time::Duration::from_millis(1);
        assert!(config.validate().is_ok());
    }
}
