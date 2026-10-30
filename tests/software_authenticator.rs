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
//! In-memory credential acceptance tests through the public adapter API.
#![cfg(feature = "webauthn-virtual")]

use himmelcloak::authenticator::software::SoftwareAuthenticator;
use himmelcloak::authenticator::{
    CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
};
use himmelcloak::Error;
use wolfssl_wolfcrypt::{ecc::ECC, sha::SHA256};

fn request(id: Vec<u8>) -> WebAuthnGetRequest {
    WebAuthnGetRequest {
        rp_id: String::from("example.com"),
        client_data_hash: [0xAB; 32],
        allow_credentials: vec![CredentialDescriptor { id }],
        user_verification: UserVerification::Preferred,
    }
}

fn digest(message: &[u8]) -> [u8; 32] {
    wolfssl_wolfcrypt::wolfcrypt_init().expect("wolfCrypt should initialize");
    let mut sha = SHA256::new().unwrap();
    sha.update(message).unwrap();
    let mut hash = [0; 32];
    sha.finalize(&mut hash).unwrap();
    hash
}

#[test]
fn stored_credential_round_trips_through_assertion_requests() {
    let authenticator = SoftwareAuthenticator::new(String::from("example.com")).unwrap();
    let credential_id = authenticator.credential_id();
    let public_key = authenticator.public_key();
    let mut verifier = ECC::import_x963(&public_key, None, None).unwrap();
    let mut request = request(credential_id.clone());
    // Independently calculated SHA-256("example.com"), without private helpers.
    let rp_id_hash = [
        0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34, 0xE2,
        0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE,
        0x19, 0x47,
    ];
    for count in [1u32, 2] {
        request.client_data_hash = [count as u8; 32];
        let assertion = authenticator.get_assertion(&request).unwrap();
        assert_eq!(assertion.credential_id, credential_id);
        assert_eq!(assertion.user_handle, None);
        assert_eq!(assertion.authenticator_data.len(), 37);
        assert_eq!(&assertion.authenticator_data[..32], &rp_id_hash);
        assert_eq!(assertion.authenticator_data[32], 0x01); // UP without UV/AT/ED.
        assert_eq!(&assertion.authenticator_data[33..], &count.to_be_bytes());
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&request.client_data_hash);
        assert!(verifier
            .verify_hash(&assertion.signature, &digest(&signed))
            .unwrap());
        signed[0] ^= 0xFF;
        assert!(!verifier
            .verify_hash(&assertion.signature, &digest(&signed))
            .unwrap());
    }
    assert_eq!(authenticator.credential_id(), credential_id);
    assert_eq!(authenticator.public_key(), public_key);
}

#[test]
fn unknown_credential_is_rejected_without_advancing_the_counter() {
    let authenticator = SoftwareAuthenticator::new(String::from("example.com")).unwrap();
    let credential_id = authenticator.credential_id();
    let mut request = request(credential_id.clone());
    let first = authenticator.get_assertion(&request).unwrap();
    assert_eq!(&first.authenticator_data[33..], &1u32.to_be_bytes());

    // Keep the RP and other fields valid to isolate the unknown credential.
    request.allow_credentials[0].id[0] ^= 0xFF;
    assert!(matches!(
        authenticator.get_assertion(&request),
        Err(Error::AuthenticationRejected)
    ));
    request.allow_credentials[0].id = credential_id.clone();
    let next = authenticator.get_assertion(&request).unwrap();
    assert_eq!(next.credential_id, credential_id);
    assert_eq!(&next.authenticator_data[33..], &2u32.to_be_bytes());
}
