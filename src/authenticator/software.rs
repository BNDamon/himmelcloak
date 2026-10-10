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
//! Software (virtual) `WebAuthnAdapter` for CI/tests, headless passkey flows, no hardware.
//! Feature: `webauthn-virtual`.

// Private state for one software credential. Keeping fields private lets future
// authenticator methods control key access and counter updates. Do not derive
// Debug or Clone here: this state contains a private signing key.
struct InMemoryCredential {
    signing_key: wolfssl_wolfcrypt::ecdsa::P256SigningKey,
    // Bind this key to one relying party, rather than using it for any RP ID.
    rp_id: String,
    // Public opaque identifier: distinct from both the private key and user ID.
    credential_id: Vec<u8>,
    // Start at zero; assertion handling will define when this counter advances.
    sign_count: u32,
}

/// A single-credential virtual authenticator for tests and headless development.
/// Its key exists only in memory and is lost when this instance is dropped.
/// Calling get_assertion simulates user presence for this virtual backend;
/// it does not perform a physical touch or user verification.
pub struct SoftwareAuthenticator {
    // The adapter receives &self, but signing and counter updates need mutable
    // state. RefCell allows checked borrowing at runtime inside that shared
    // reference. It is for single-threaded use, not concurrent shared access.
    credential: std::cell::RefCell<InMemoryCredential>,
}

impl SoftwareAuthenticator {
    /// Provision one fresh credential locally, without a registration protocol.
    pub fn new(rp_id: String) -> crate::Result<Self> {
        let credential = InMemoryCredential::new(rp_id)?;
        Ok(Self {
            credential: std::cell::RefCell::new(credential),
        })
    }

    /// Copy the public credential ID for use in an allowed-credentials list.
    pub fn credential_id(&self) -> Vec<u8> {
        // borrow() grants temporary read access. clone() returns an owned ID so
        // the caller does not need to hold a borrow of our internal state.
        self.credential.borrow().credential_id.clone()
    }
}

impl super::WebAuthnAdapter for SoftwareAuthenticator {
    fn get_assertion(
        &self,
        request: &super::WebAuthnGetRequest,
    ) -> crate::Result<super::WebAuthnAssertion> {
        use signature::SignerMut;
        use wolfssl_wolfcrypt::ecdsa::P256Signature;

        // Borrow mutable state without panicking if another borrow is active.
        // The guard releases its borrow automatically when this method returns.
        let mut credential = self
            .credential
            .try_borrow_mut()
            .map_err(|_| crate::Error::AuthenticationRejected)?;
        credential.validate_request(request)?;
        // Never wrap the counter back to zero. Do not commit it until all
        // fallible signing and encoding operations have succeeded.
        let next_count = credential
            .sign_count
            .checked_add(1)
            .ok_or(crate::Error::AuthenticationRejected)?;
        let data = assertion_authenticator_data(&credential.rp_id, false, next_count)?;

        // WebAuthn signs authenticatorData followed by the client's data hash.
        // SignerMut hashes this combined message internally with SHA-256.
        let mut message = Vec::with_capacity(37 + 32);
        message.extend_from_slice(&data);
        message.extend_from_slice(&request.client_data_hash);
        let raw_signature: P256Signature = credential
            .signing_key
            .try_sign(&message)
            .map_err(|_| crate::Error::Crypto)?;

        // The signing wrapper exposes 64 raw r || s bytes, while an ES256
        // WebAuthn assertion uses an ASN.1 DER sequence of the two integers.
        // Use wolfCrypt's existing encoder rather than hand-writing DER rules.
        let raw = raw_signature.as_ref();
        let mut der = [0u8; 72];
        let length = wolfssl_wolfcrypt::ecc::ECC::rs_bin_to_sig(&raw[..32], &raw[32..], &mut der)
            .map_err(|_| crate::Error::Crypto)?;
        let assertion = super::WebAuthnAssertion {
            authenticator_data: data.to_vec(),
            signature: der[..length].to_vec(),
            credential_id: credential.credential_id.clone(),
            // This initial backend handles only explicitly allowed credentials.
            user_handle: None,
        };
        credential.sign_count = next_count;
        Ok(assertion)
    }
}

impl InMemoryCredential {
    // Validate the request against this stored credential before signing.
    // This initial authenticator has no user-verification mechanism and only
    // handles explicitly allowed credentials (no discoverable-credential flow).
    fn validate_request(&self, request: &super::WebAuthnGetRequest) -> crate::Result<()> {
        if request.rp_id != self.rp_id {
            return Err(crate::Error::AuthenticationRejected);
        }
        // any() succeeds when at least one allowed ID matches our stored ID.
        // An empty list also fails under the explicit-credential policy above.
        if !request
            .allow_credentials
            .iter()
            .any(|allowed| allowed.id == self.credential_id)
        {
            return Err(crate::Error::AuthenticationRejected);
        }
        // matches! checks an enum variant. Required verification cannot be
        // satisfied just by setting the UV bit: real verification must happen.
        if matches!(request.user_verification, super::UserVerification::Required) {
            return Err(crate::Error::AuthenticationRejected);
        }
        Ok(())
    }

    // This is local provisioning for tests, not a CTAP makeCredential handler.
    // Accept an owned String so the credential can retain its RP binding.
    fn new(rp_id: String) -> crate::Result<Self> {
        // random_bytes initializes wolfCrypt and generates a fresh opaque ID.
        // The 32-byte ID length is our implementation choice, not a private key.
        let credential_id = crate::crypto::random_bytes::<32>()?.to_vec();
        let rng = wolfssl_wolfcrypt::random::RNG::new().map_err(|_| crate::Error::Crypto)?;
        let signing_key = wolfssl_wolfcrypt::ecdsa::P256SigningKey::generate(rng)
            .map_err(|_| crate::Error::Crypto)?;
        Ok(Self {
            signing_key,
            rp_id,
            credential_id,
            sign_count: 0,
        })
    }
}

// Charter Tables 6 and 7: an assertion without extensions has a 32-byte RP ID
// hash, one flags byte, and a four-byte signature counter. Registration data
// and extensions are deliberately not appended by this layout helper.
fn build_assertion_authenticator_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    sign_count: u32,
) -> [u8; 37] {
    // Initialize the whole fixed-size output, then fill each field at its offset.
    let mut data = [0u8; 37];
    data[..32].copy_from_slice(rp_id_hash);
    data[32] = flags;
    // to_be_bytes writes the most significant counter byte first, independent
    // of the machine's native byte order. The range 33..37 excludes index 37.
    data[33..37].copy_from_slice(&sign_count.to_be_bytes());
    // This only assembles bytes. The caller must compute SHA-256(rpId) and
    // choose flags consistent with actual presence/verification and no AT/ED.
    data
}

// Build this software authenticator's assertion bytes from the RP ID itself.
// The caller supplies whether user verification actually succeeded; this helper
// does not perform verification or establish user presence. Its current policy
// assumes presence was established and emits no backup, registration, or extension bits.
fn assertion_authenticator_data(
    rp_id: &str,
    user_verified: bool,
    sign_count: u32,
) -> crate::Result<[u8; 37]> {
    // as_bytes borrows the string's UTF-8 bytes. Hash the RP ID, not a URL or
    // the client data hash. Reuse the project's initialized wolfCrypt helper.
    let rp_id_hash = crate::crypto::sha256(rp_id.as_bytes())?;
    // UP is bit 0 (0x01); UV is bit 2 (0x04). | combines the set bits.
    let flags = if user_verified { 0x01 | 0x04 } else { 0x01 };
    Ok(build_assertion_authenticator_data(
        &rp_id_hash,
        flags,
        sign_count,
    ))
}

// Compile this module only for tests. Each #[test] function is a test entry point.
#[cfg(test)]
mod tests {
    // Import names from the parent module, including its private helper functions.
    use super::*;

    #[test]
    fn test_software_assertion_signing_and_counter() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };
        use signature::Keypair;
        use wolfssl_wolfcrypt::ecc::ECC;

        let authenticator = SoftwareAuthenticator::new(String::from("example.com"))
            .expect("authenticator creation should succeed");
        let mut request = WebAuthnGetRequest {
            rp_id: String::from("example.com"),
            client_data_hash: [0xAB; 32],
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Preferred,
        };
        // Verify the returned DER signature using a separate ECC verifier with
        // only the public key. No private key is exported for this check.
        let public_key = authenticator
            .credential
            .borrow()
            .signing_key
            .verifying_key();
        let mut verifier = ECC::import_x963(public_key.as_ref(), None, None)
            .expect("public key import should succeed");
        for count in [1u32, 2] {
            let assertion = authenticator
                .get_assertion(&request)
                .expect("assertion should succeed");
            assert_eq!(assertion.credential_id, authenticator.credential_id());
            assert_eq!(assertion.user_handle, None);
            assert_eq!(
                assertion.authenticator_data,
                assertion_authenticator_data("example.com", false, count)
                    .unwrap()
                    .to_vec()
            );
            let mut message = assertion.authenticator_data.clone();
            message.extend_from_slice(&request.client_data_hash);
            let hash = crate::crypto::sha256(&message).unwrap();
            assert!(verifier.verify_hash(&assertion.signature, &hash).unwrap());
            // Tampering with the client-data portion must invalidate the signature.
            message[37] ^= 0xFF;
            let changed_hash = crate::crypto::sha256(&message).unwrap();
            assert!(!verifier
                .verify_hash(&assertion.signature, &changed_hash)
                .unwrap());
        }
        // A rejected request must not consume a counter value.
        request.rp_id = String::from("other.example");
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert_eq!(authenticator.credential.borrow().sign_count, 2);
        request.rp_id = String::from("example.com");
        // Overflow must also fail without changing the stored counter.
        authenticator.credential.borrow_mut().sign_count = u32::MAX;
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert_eq!(authenticator.credential.borrow().sign_count, u32::MAX);
    }

    #[test]
    fn test_credential_request_validation() {
        // A valid request binds the stored credential to the same RP and lists
        // its public ID. Preferred verification permits proceeding without UV.
        let credential = InMemoryCredential::new(String::from("example.com"))
            .expect("credential creation should succeed");
        let mut request = super::super::WebAuthnGetRequest {
            rp_id: String::from("example.com"),
            client_data_hash: [0xAB; 32],
            allow_credentials: vec![super::super::CredentialDescriptor {
                id: credential.credential_id.clone(),
            }],
            user_verification: super::super::UserVerification::Preferred,
        };
        assert_eq!(credential.validate_request(&request), Ok(()));

        // Reject a different service even if it supplies the correct credential ID.
        request.rp_id = String::from("other.example");
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        request.rp_id = String::from("example.com");

        // Reject an ID that differs from this credential; restore it afterward
        // so the following assertion isolates the verification requirement.
        request.allow_credentials[0].id[0] ^= 0xFF;
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        request.allow_credentials[0].id = credential.credential_id.clone();
        request.user_verification = super::super::UserVerification::Required;
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );

        // Discouraged verification is acceptable, but an empty allowed list is
        // outside this initial authenticator's explicit-credential scope.
        request.user_verification = super::super::UserVerification::Discouraged;
        assert_eq!(credential.validate_request(&request), Ok(()));
        request.allow_credentials.clear();
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        // Validation must not advance the signature counter.
        assert_eq!(credential.sign_count, 0);
    }

    #[test]
    fn test_software_authenticator_creation() {
        // Provision the wrapper and retrieve the ID without exposing the key.
        let authenticator = SoftwareAuthenticator::new(String::from("example.com"))
            .expect("software authenticator creation should succeed");
        let mut id = authenticator.credential_id();
        assert_eq!(id.len(), 32);

        // Each call returns a copy of the same stored ID. Changing the copy
        // must not change the authenticator's identity.
        let stored_id = authenticator.credential_id();
        assert_eq!(id, stored_id);
        id[0] ^= 0xFF;
        assert_eq!(authenticator.credential_id(), stored_id);
    }

    #[test]
    fn test_in_memory_credential_creation() {
        use signature::{Keypair, SignerMut, Verifier};
        use wolfssl_wolfcrypt::ecdsa::P256Signature;

        // Check provisioning metadata without printing or exporting the private key.
        let mut credential = InMemoryCredential::new(String::from("example.com"))
            .expect("credential creation should succeed");
        assert_eq!(credential.rp_id, "example.com");
        assert_eq!(credential.credential_id.len(), 32);
        assert_eq!(credential.sign_count, 0);

        // The stored key must actually work; field checks alone cannot prove that.
        let public_key = credential.signing_key.verifying_key();
        let message = b"credential key test";
        let signature: P256Signature = credential
            .signing_key
            .try_sign(message)
            .expect("stored key should sign");
        public_key
            .verify(message, &signature)
            .expect("stored key's public key should verify");
        // Signing in this low-level test does not itself update our counter.
        assert_eq!(credential.sign_count, 0);
    }

    #[test]
    fn test_es256_sign_and_verify() {
        // Traits provide these methods on the wolfCrypt types. Importing a
        // trait brings its methods into scope, much like choosing an interface.
        use signature::{Keypair, SignerMut, Verifier};
        use wolfssl_wolfcrypt::ecdsa::{P256Signature, P256SigningKey};
        use wolfssl_wolfcrypt::random::RNG;

        // The project's random helper initializes wolfCrypt through its shared
        // initialization path. Keep this test's setup local to the test.
        crate::crypto::random_bytes::<1>().expect("wolfCrypt initialization should succeed");
        let rng = RNG::new().expect("secure random generator should initialize");
        // generate takes ownership of the RNG. The key keeps it for signing.
        // mut is required because signing needs mutable access to that key.
        let mut key = P256SigningKey::generate(rng).expect("P-256 key generation should succeed");
        let public_key = key.verifying_key();

        // b"..." is a byte-string literal. try_sign hashes these message bytes
        // with SHA-256 internally; supplying a precomputed digest would hash twice.
        let message = b"Himmelcloak ES256 signing test";
        let signature: P256Signature = key.try_sign(message).expect("ES256 signing should succeed");
        public_key
            .verify(message, &signature)
            .expect("matching message should verify");

        // Reuse the signature with different message bytes: verification must
        // fail, demonstrating that the signature is bound to the signed message.
        assert!(public_key.verify(b"changed message", &signature).is_err());
        // This wrapper returns raw r || s bytes. WebAuthn's DER signature
        // encoding will need separate attention when we build an assertion.
    }

    #[test]
    fn test_assertion_authenticator_data_rp_id_hash() {
        // This expected SHA-256("example.com") was calculated independently
        // with Python hashlib, not with the helper being tested.
        // The final five bytes are UP alone and a big-endian counter of 1.
        let expected = [
            0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34,
            0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55,
            0x86, 0xCE, 0x19, 0x47, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let actual = assertion_authenticator_data("example.com", false, 1)
            .expect("RP ID hashing should succeed");
        assert_eq!(actual, expected);

        // Successful verification changes only the UV flag. A zero counter
        // checks the all-zero encoding without changing the known RP hash.
        let mut verified_expected = expected;
        verified_expected[32] = 0x05;
        verified_expected[33..37].copy_from_slice(&[0, 0, 0, 0]);
        let verified = assertion_authenticator_data("example.com", true, 0)
            .expect("RP ID hashing should succeed");
        assert_eq!(verified, verified_expected);
    }

    #[test]
    fn test_assertion_authenticator_data_layout() {
        // Distinct hash bytes expose misplaced offsets or incomplete copies.
        // This is a layout fixture, not an actual SHA-256 result for an RP ID.
        let rp_id_hash = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        // Bit 0 is UP; bit 2 is UV. Other bits are zero in these examples.
        // Test both user-present-only and user-present-and-verified layouts.
        for flags in [0x01, 0x05] {
            let actual = build_assertion_authenticator_data(&rp_id_hash, flags, 0x01020304);
            // Spell out all 37 expected bytes rather than rebuilding them with
            // the helper's copy/endian operations, so a layout error is visible.
            let expected = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F, flags, 0x01, 0x02, 0x03, 0x04,
            ];
            assert_eq!(actual, expected);
        }
    }
}
