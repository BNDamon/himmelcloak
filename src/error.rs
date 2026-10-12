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
