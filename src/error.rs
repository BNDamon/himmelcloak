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
use core::fmt;

/// Errors deliberately omit response bodies and credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidConfiguration(&'static str),
    Transport(String),
    /// The request never reached Keycloak: its host name did not resolve, or no connection
    /// could be made, and no byte of the request was sent. Unlike `Transport`, repeating the
    /// request is safe. Certificate and TLS failures are never this.
    Unreachable(String),
    TlsBackend,
    HttpStatus(u32),
    AuthenticationRejected,
    Protocol(&'static str),
    TokenValidation(&'static str),
    Crypto,
    UnsupportedFactor,
    Cancelled,
    Expired,
    NotImplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => write!(f, "invalid configuration: {reason}"),
            Self::Transport(reason) => write!(f, "transport error: {reason}"),
            Self::Unreachable(reason) => write!(f, "Keycloak unreachable: {reason}"),
            Self::TlsBackend => write!(f, "libcurl is not using wolfSSL"),
            Self::HttpStatus(status) => write!(f, "unexpected HTTP status {status}"),
            Self::AuthenticationRejected => write!(f, "authentication rejected"),
            Self::Protocol(reason) => write!(f, "OIDC protocol error: {reason}"),
            Self::TokenValidation(reason) => write!(f, "token validation failed: {reason}"),
            Self::Crypto => write!(f, "wolfCrypt operation failed"),
            Self::UnsupportedFactor => write!(f, "authentication factor not supported"),
            Self::Cancelled => write!(f, "login cancelled"),
            Self::Expired => write!(f, "login expired"),
            Self::NotImplemented => write!(f, "not implemented"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn every_error_has_a_readable_message() {
        for (error, message) in [
            (
                Error::InvalidConfiguration("no realm"),
                "invalid configuration: no realm",
            ),
            (Error::Transport("reset".into()), "transport error: reset"),
            (
                Error::Unreachable("refused".into()),
                "Keycloak unreachable: refused",
            ),
            (Error::TlsBackend, "libcurl is not using wolfSSL"),
            (Error::HttpStatus(503), "unexpected HTTP status 503"),
            (Error::AuthenticationRejected, "authentication rejected"),
            (Error::Protocol("bad page"), "OIDC protocol error: bad page"),
            (
                Error::TokenValidation("expired"),
                "token validation failed: expired",
            ),
            (Error::Crypto, "wolfCrypt operation failed"),
            (
                Error::UnsupportedFactor,
                "authentication factor not supported",
            ),
            (Error::Cancelled, "login cancelled"),
            (Error::Expired, "login expired"),
            (Error::NotImplemented, "not implemented"),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }
}
