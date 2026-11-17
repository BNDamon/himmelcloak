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
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use signature::Verifier;
use wolfssl_wolfcrypt::aes::GCM;
use wolfssl_wolfcrypt::ecdsa::{P256Signature, P256VerifyingKey};
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha256, Signature as RsaSignature, VerifyingKey};
use wolfssl_wolfcrypt::sha::SHA256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

fn init() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), i32>> = OnceLock::new();
    INIT.get_or_init(wolfssl_wolfcrypt::wolfcrypt_init)
        .as_ref()
        .map_err(|_| Error::Crypto)
        .copied()
}

pub(crate) fn sha256(data: &[u8]) -> Result<[u8; 32]> {
    init()?;
    let mut sha = SHA256::new().map_err(|_| Error::Crypto)?;
    sha.update(data).map_err(|_| Error::Crypto)?;
    let mut digest = [0u8; 32];
    sha.finalize(&mut digest).map_err(|_| Error::Crypto)?;
    Ok(digest)
}

/// Create a secure RNG after initializing wolfCrypt through the shared path.
pub(crate) fn rng() -> Result<RNG> {
    init()?;
    RNG::new().map_err(|_| Error::Crypto)
}

pub(crate) fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let rng = rng()?;
    let mut output = Zeroizing::new([0u8; N]);
    rng.generate_block(&mut *output)
        .map_err(|_| Error::Crypto)?;
    Ok(output)
}

/// AES-GCM encryption: the ciphertext and its 16-byte tag, which also covers `aad`.
pub(crate) fn aes_gcm_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    init()?;
    let mut gcm = GCM::new().map_err(|_| Error::Crypto)?;
    gcm.init(key).map_err(|_| Error::Crypto)?;
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    let sealed = gcm.encrypt(plaintext, &mut ciphertext, nonce, aad, &mut tag);
    sealed.map_err(|_| Error::Crypto)?;
    Ok((ciphertext, tag))
}

/// AES-GCM decryption. Fails with `Crypto` when the ciphertext, tag, nonce, or `aad` were
/// altered; the plaintext is wiped when dropped.
pub(crate) fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    init()?;
    let mut gcm = GCM::new().map_err(|_| Error::Crypto)?;
    gcm.init(key).map_err(|_| Error::Crypto)?;
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    gcm.decrypt(ciphertext, &mut plaintext, nonce, aad, tag)
        .map_err(|_| Error::Crypto)?;
    Ok(plaintext)
}

pub(crate) fn verify(alg: &str, jwk: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
    init()?;
    match alg {
        "RS256" => verify_rsa(jwk, message, signature),
        "ES256" => verify_ec(jwk, message, signature),
        _ => Err(Error::TokenValidation("unsupported signing algorithm")),
    }
}

fn field(jwk: &Value, name: &str) -> Result<Vec<u8>> {
    let encoded = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing JWK field"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::TokenValidation("invalid JWK encoding"))
}

fn verify_rsa(jwk: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
    if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err(Error::TokenValidation("JWK type does not match algorithm"));
    }
    let modulus = field(jwk, "n")?;
    let exponent = field(jwk, "e")?;
    match modulus.len() {
        256 => verify_rsa_size::<256>(&modulus, &exponent, message, signature),
        384 => verify_rsa_size::<384>(&modulus, &exponent, message, signature),
        512 => verify_rsa_size::<512>(&modulus, &exponent, message, signature),
        _ => Err(Error::TokenValidation("unsupported RSA key size")),
    }
}

fn verify_rsa_size<const N: usize>(n: &[u8], e: &[u8], message: &[u8], bytes: &[u8]) -> Result<()> {
    let key = VerifyingKey::<Sha256, N>::from_components(n, e)
        .map_err(|_| Error::TokenValidation("invalid RSA key"))?;
    let signature = RsaSignature::<N>::try_from(bytes)
        .map_err(|_| Error::TokenValidation("invalid RSA signature length"))?;
    key.verify(message, &signature)
        .map_err(|_| Error::TokenValidation("invalid signature"))
}

fn verify_ec(jwk: &Value, message: &[u8], bytes: &[u8]) -> Result<()> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(Error::TokenValidation("JWK curve does not match algorithm"));
    }
    let x = field(jwk, "x")?;
    let y = field(jwk, "y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::TokenValidation("invalid P-256 point"));
    }
    let mut public = [0u8; 65];
    public[0] = 4;
    public[1..33].copy_from_slice(&x);
    public[33..].copy_from_slice(&y);
    let key = P256VerifyingKey::from_bytes(public);
    let signature = P256Signature::try_from(bytes)
        .map_err(|_| Error::TokenValidation("invalid ECDSA signature length"))?;
    key.verify(message, &signature)
        .map_err(|_| Error::TokenValidation("invalid signature"))
}

#[cfg(test)]
mod tests {
    use super::{aes_gcm_open, aes_gcm_seal};
    use crate::error::Error;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes_gcm_matches_the_nist_test_vector_and_detects_tampering() {
        // NIST GCM test vector (AES-128, 96-bit IV, 128-bit AAD).
        let key = hex("298efa1ccf29cf62ae6824bfc19557fc");
        let nonce = hex("6f58a93fe1d207fae4ed2f6d");
        let plaintext = hex("cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901");
        let aad = hex("021fafd238463973ffe80256e5b1c6b1");
        let (ciphertext, tag) = aes_gcm_seal(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(
            ciphertext,
            hex("dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db")
        );
        assert_eq!(tag.to_vec(), hex("542465ef599316f73a7a560509a2d9f2"));
        assert_eq!(
            *aes_gcm_open(&key, &nonce, &aad, &ciphertext, &tag).unwrap(),
            plaintext
        );

        let mut altered = ciphertext.clone();
        altered[0] ^= 1;
        assert_eq!(
            aes_gcm_open(&key, &nonce, &aad, &altered, &tag).err(),
            Some(Error::Crypto)
        );
        assert_eq!(
            aes_gcm_open(&key, &nonce, b"other data", &ciphertext, &tag).err(),
            Some(Error::Crypto)
        );
        // A key of the wrong size is refused rather than used.
        assert_eq!(
            aes_gcm_seal(&key[..15], &nonce, &aad, &plaintext).err(),
            Some(Error::Crypto)
        );
        assert_eq!(
            aes_gcm_open(&key[..15], &nonce, &aad, &ciphertext, &tag).err(),
            Some(Error::Crypto)
        );
    }
}
