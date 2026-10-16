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
//! TOTP/HOTP factor. Feature: `totp`.
//! Direct-grant `totp` param (fast path) OR the flow-driver OTP step.
//! `Challenge::OneTimeCode` / `Answer::OneTimeCode`.

use std::sync::OnceLock;

use wolfssl_wolfcrypt::hmac::HMAC;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Hash algorithms supported by Keycloak-compatible OTP credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    fn wolfcrypt_type(self) -> i32 {
        match self {
            Self::Sha1 => HMAC::TYPE_SHA,
            Self::Sha256 => HMAC::TYPE_SHA256,
            Self::Sha512 => HMAC::TYPE_SHA512,
        }
    }
}

/// Generate an HOTP code for one counter value.
pub(crate) fn hotp(
    secret: &[u8],
    counter: u64,
    algorithm: OtpAlgorithm,
    digits: u32,
) -> Result<Zeroizing<String>> {
    if secret.len() < 16 {
        return Err(Error::InvalidConfiguration(
            "OTP secret must be at least 16 bytes",
        ));
    }
    if !(6..=8).contains(&digits) {
        return Err(Error::InvalidConfiguration(
            "OTP digit count must be between 6 and 8",
        ));
    }

    let digest = hmac(algorithm.wolfcrypt_type(), secret, &counter.to_be_bytes())?;
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);

    let value = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;

    Ok(Zeroizing::new(format!(
        "{value:0width$}",
        value = value % 10_u32.pow(digits),
        width = digits as usize
    )))
}

/// Generate a TOTP code for a Unix timestamp and time period.
pub(crate) fn totp(
    secret: &[u8],
    unix_time: u64,
    period: u32,
    algorithm: OtpAlgorithm,
    digits: u32,
) -> Result<Zeroizing<String>> {
    if period == 0 {
        return Err(Error::InvalidConfiguration("OTP period must not be zero"));
    }

    hotp(secret, unix_time / u64::from(period), algorithm, digits)
}

/// Check whether a user-provided HOTP code matches the expected code.
pub(crate) fn verify_hotp(
    secret: &[u8],
    counter: u64,
    algorithm: OtpAlgorithm,
    digits: u32,
    code: &str,
) -> Result<bool> {
    Ok(constant_time_eq(
        hotp(secret, counter, algorithm, digits)?.as_bytes(),
        code.as_bytes(),
    ))
}

/// Verify an HOTP code and advance the counter only after a match.
pub(crate) fn verify_and_advance_hotp(
    secret: &[u8],
    counter: &mut u64,
    algorithm: OtpAlgorithm,
    digits: u32,
    code: &str,
) -> Result<bool> {
    let matched = verify_hotp(secret, *counter, algorithm, digits, code)?;

    if matched {
        *counter = counter
            .checked_add(1)
            .ok_or(Error::InvalidConfiguration("HOTP counter exhausted"))?;
    }

    Ok(matched)
}

/// Check whether a user-provided TOTP code matches the expected code.
pub(crate) fn verify_totp(
    secret: &[u8],
    unix_time: u64,
    period: u32,
    algorithm: OtpAlgorithm,
    digits: u32,
    code: &str,
) -> Result<bool> {
    Ok(constant_time_eq(
        totp(secret, unix_time, period, algorithm, digits)?.as_bytes(),
        code.as_bytes(),
    ))
}

fn init() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), i32>> = OnceLock::new();

    INIT.get_or_init(wolfssl_wolfcrypt::wolfcrypt_init)
        .as_ref()
        .map_err(|_| Error::Crypto)
        .copied()
}

fn hmac(hash_type: i32, key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    init()?;

    let mut hmac = HMAC::new(hash_type, key).map_err(|_| Error::Crypto)?;
    hmac.update(data).map_err(|_| Error::Crypto)?;

    let mut output = Zeroizing::new(vec![0u8; hmac.get_hmac_size().map_err(|_| Error::Crypto)?]);
    hmac.finalize(&mut output).map_err(|_| Error::Crypto)?;

    Ok(output)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;
    for (&left_byte, &right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }

    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{hotp, totp, verify_and_advance_hotp, verify_hotp, verify_totp, OtpAlgorithm};

    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn totp_matches_rfc_6238_sha1_vector() {
        assert!(
            verify_totp(SECRET, 59, 30, OtpAlgorithm::Sha1, 8, "94287082",)
                .expect("valid TOTP input")
        );
    }

    #[test]
    fn totp_matches_rfc_6238_sha256_vector() {
        assert!(verify_totp(
            b"12345678901234567890123456789012",
            59,
            30,
            OtpAlgorithm::Sha256,
            8,
            "46119246",
        )
        .expect("valid TOTP input"));
    }

    #[test]
    fn totp_matches_rfc_6238_sha512_vector() {
        assert!(verify_totp(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            59,
            30,
            OtpAlgorithm::Sha512,
            8,
            "90693936",
        )
        .expect("valid TOTP input"));
    }

    #[test]
    fn rejects_incorrect_totp_code() {
        assert!(
            !verify_totp(SECRET, 59, 30, OtpAlgorithm::Sha1, 8, "00000000",)
                .expect("valid TOTP input")
        );
    }

    #[test]
    fn rejects_invalid_otp_configuration() {
        let short_secret = b"123456789012345";
        let minimum_secret = b"1234567890123456";

        for (secret, digits, should_succeed) in [
            (&short_secret[..], 6, false),
            (&minimum_secret[..], 6, true),
            (SECRET, 5, false),
            (SECRET, 9, false),
        ] {
            assert_eq!(
                hotp(secret, 0, OtpAlgorithm::Sha1, digits).is_ok(),
                should_succeed,
            );
        }

        assert!(totp(SECRET, 0, 0, OtpAlgorithm::Sha1, 6).is_err());
    }

    #[test]
    fn hotp_advances_the_counter_after_a_valid_code() {
        let mut counter = 0;

        assert_eq!(
            hotp(SECRET, counter, OtpAlgorithm::Sha1, 6)
                .expect("valid HOTP input")
                .as_str(),
            "755224"
        );

        assert!(
            verify_and_advance_hotp(SECRET, &mut counter, OtpAlgorithm::Sha1, 6, "755224",)
                .expect("valid HOTP input")
        );
        assert_eq!(counter, 1);

        assert!(
            verify_and_advance_hotp(SECRET, &mut counter, OtpAlgorithm::Sha1, 6, "287082",)
                .expect("valid HOTP input")
        );
        assert_eq!(counter, 2);
    }

    #[test]
    fn rejected_hotp_code_does_not_advance_counter() {
        let mut counter = 0;

        assert!(
            !verify_hotp(SECRET, counter, OtpAlgorithm::Sha1, 6, "000000")
                .expect("valid HOTP input")
        );
        assert!(
            !verify_and_advance_hotp(SECRET, &mut counter, OtpAlgorithm::Sha1, 6, "000000",)
                .expect("valid HOTP input")
        );
        assert_eq!(counter, 0);
    }

    #[test]
    fn exhausted_hotp_counter_does_not_advance() {
        let mut counter = u64::MAX;
        let code = hotp(SECRET, counter, OtpAlgorithm::Sha1, 6).expect("valid HOTP input");

        assert!(verify_and_advance_hotp(
            SECRET,
            &mut counter,
            OtpAlgorithm::Sha1,
            6,
            code.as_str(),
        )
        .is_err());
        assert_eq!(counter, u64::MAX);
    }
}
