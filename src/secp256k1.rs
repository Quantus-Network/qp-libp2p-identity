// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Secp256k1 keys.

use super::error::DecodingError;
use asn1_der::typed::{DerDecodable, Sequence};
use core::cmp;
use core::fmt;
use core::hash;
use libsecp256k1::{Message, Signature};
use sha2::{Digest as ShaDigestTrait, Sha256};
use zeroize::Zeroize;

/// A Secp256k1 keypair.
#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    /// Generate a new sec256k1 `Keypair`.
    #[cfg(feature = "rand")]
    pub fn generate() -> Keypair {
        Keypair::from(SecretKey::generate())
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish()
    }
}

/// Promote a Secp256k1 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = PublicKey(libsecp256k1::PublicKey::from_secret_key(&secret.0));
        Keypair { secret, public }
    }
}

/// Demote a Secp256k1 keypair into a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        kp.secret
    }
}

/// A Secp256k1 secret key.
#[derive(Clone)]
pub struct SecretKey(libsecp256k1::SecretKey);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    /// Generate a new random Secp256k1 secret key.
    #[cfg(feature = "rand")]
    pub fn generate() -> SecretKey {
        SecretKey(libsecp256k1::SecretKey::random(&mut rand::thread_rng()))
    }

    /// Create a secret key from a byte slice, zeroing the slice on success.
    /// If the bytes do not constitute a valid Secp256k1 secret key, an
    /// error is returned.
    ///
    /// Note that the expected binary format is the same as `libsecp256k1`'s.
    pub fn try_from_bytes(mut sk: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
        let sk_bytes = sk.as_mut();
        let secret = libsecp256k1::SecretKey::parse_slice(&*sk_bytes)
            .map_err(|e| DecodingError::failed_to_parse("parse secp256k1 secret key", e))?;
        sk_bytes.zeroize();
        Ok(SecretKey(secret))
    }

    /// Decode a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915], zeroing the input slice on success.
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    pub fn from_der(mut der: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
        let der_obj = der.as_mut();

        let seq = Sequence::decode(der_obj)
            .map_err(|e| DecodingError::failed_to_parse("secp256k1 ECPrivateKey SEQUENCE", e))?;

        // Get the private key octet string (element at index 1 in ECPrivateKey)
        let pk_obj = seq
            .get(1)
            .map_err(|e| DecodingError::failed_to_parse("secp256k1 privateKey field", e))?;

        // Verify it's an OCTET STRING (tag 0x04)
        if pk_obj.tag() != 4 {
            return Err(DecodingError::new(
                "secp256k1 privateKey is not an OCTET STRING".to_string(),
            ));
        }

        // Check the size BEFORE allocating - secp256k1 secret keys are exactly 32 bytes
        let pk_value = pk_obj.value();
        if pk_value.len() != 32 {
            return Err(DecodingError::new(format!(
                "secp256k1 privateKey has invalid length: expected 32 bytes, got {}",
                pk_value.len()
            )));
        }

        // Now we can safely copy into a fixed-size array (no heap allocation for key material)
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(pk_value);

        let sk = SecretKey::try_from_bytes(&mut sk_bytes)?;
        sk_bytes.zeroize();
        der_obj.zeroize();
        Ok(sk)
    }

    /// Sign a message with this secret key, producing a DER-encoded
    /// ECDSA signature, as defined in [RFC3278].
    ///
    /// [RFC3278]: https://tools.ietf.org/html/rfc3278#section-8.2
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let generic_array = Sha256::digest(msg);

        // FIXME: Once `generic-array` hits 1.0, we should be able to just use `Into` here.
        let mut array = [0u8; 32];
        array.copy_from_slice(generic_array.as_slice());

        let message = Message::parse(&array);

        libsecp256k1::sign(&message, &self.0)
            .0
            .serialize_der()
            .as_ref()
            .into()
    }

    /// Returns the raw bytes of the secret key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.serialize()
    }
}

/// A Secp256k1 public key.
#[derive(Eq, Clone)]
pub struct PublicKey(libsecp256k1::PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(compressed): ")?;
        for byte in &self.to_bytes() {
            write!(f, "{byte:x}")?;
        }
        Ok(())
    }
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl hash::Hash for PublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl cmp::PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for PublicKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PublicKey {
    /// Verify the Secp256k1 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.verify_hash(Sha256::digest(msg).as_ref(), sig)
    }

    /// Verify the Secp256k1 DER-encoded signature on a raw 256-bit message using the public key.
    pub fn verify_hash(&self, msg: &[u8], sig: &[u8]) -> bool {
        Message::parse_slice(msg)
            .and_then(|m| Signature::parse_der(sig).map(|s| libsecp256k1::verify(&m, &s, &self.0)))
            .unwrap_or(false)
    }

    /// Convert the public key to a byte buffer in compressed form, i.e. with one coordinate
    /// represented by a single bit.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.serialize_compressed()
    }

    /// Convert the public key to a byte buffer in uncompressed form.
    pub fn to_bytes_uncompressed(&self) -> [u8; 65] {
        self.0.serialize()
    }

    /// Decode a public key from a byte slice in the the format produced
    /// by `encode`.
    pub fn try_from_bytes(k: &[u8]) -> Result<PublicKey, DecodingError> {
        libsecp256k1::PublicKey::parse_slice(k, Some(libsecp256k1::PublicKeyFormat::Compressed))
            .map_err(|e| DecodingError::failed_to_parse("secp256k1 public key", e))
            .map(PublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand")]
    fn secp256k1_secret_from_bytes() {
        let sk1 = SecretKey::generate();
        let mut sk_bytes = [0; 32];
        sk_bytes.copy_from_slice(&sk1.0.serialize()[..]);
        let sk2 = SecretKey::try_from_bytes(&mut sk_bytes).unwrap();
        assert_eq!(sk1.0.serialize(), sk2.0.serialize());
        assert_eq!(sk_bytes, [0; 32]);
    }

    #[test]
    fn secp256k1_reject_oversized_der_private_key() {
        // Construct a malicious ECPrivateKey DER structure with an oversized private key field
        // ECPrivateKey ::= SEQUENCE {
        //   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //   privateKey     OCTET STRING,  <- This should be exactly 32 bytes
        //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //   publicKey  [1] BIT STRING OPTIONAL
        // }

        // Build an ECPrivateKey with a 64-byte (oversized) private key
        let oversized_key = vec![0xAB; 64]; // 64 bytes instead of 32

        let mut der = Vec::new();
        // SEQUENCE tag
        der.push(0x30);

        // Calculate inner length
        let version_len = 3; // INTEGER 1
        let pk_len = 2 + oversized_key.len(); // OCTET STRING header + data
        let inner_len = version_len + pk_len;

        // Length (short form since < 128)
        der.push(inner_len as u8);

        // version INTEGER = 1
        der.push(0x02); // INTEGER tag
        der.push(0x01); // length 1
        der.push(0x01); // value 1

        // privateKey OCTET STRING (oversized)
        der.push(0x04); // OCTET STRING tag
        der.push(oversized_key.len() as u8); // length
        der.extend_from_slice(&oversized_key);

        let result = SecretKey::from_der(&mut der);
        assert!(result.is_err(), "Oversized secp256k1 private key should be rejected");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid length") || err_msg.contains("32"),
            "Error should mention invalid length, got: {}",
            err_msg
        );
    }

    #[test]
    fn secp256k1_reject_undersized_der_private_key() {
        // Build an ECPrivateKey with a 16-byte (undersized) private key
        let undersized_key = vec![0xAB; 16]; // 16 bytes instead of 32

        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE

        let version_len = 3;
        let pk_len = 2 + undersized_key.len();
        let inner_len = version_len + pk_len;
        der.push(inner_len as u8);

        // version
        der.push(0x02);
        der.push(0x01);
        der.push(0x01);

        // privateKey OCTET STRING (undersized)
        der.push(0x04);
        der.push(undersized_key.len() as u8);
        der.extend_from_slice(&undersized_key);

        let result = SecretKey::from_der(&mut der);
        assert!(result.is_err(), "Undersized secp256k1 private key should be rejected");
    }

    #[test]
    fn secp256k1_reject_non_octet_string_private_key() {
        // Build an ECPrivateKey where the private key field is not an OCTET STRING
        let fake_key = vec![0xAB; 32];

        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE

        let version_len = 3;
        let pk_len = 2 + fake_key.len();
        let inner_len = version_len + pk_len;
        der.push(inner_len as u8);

        // version
        der.push(0x02);
        der.push(0x01);
        der.push(0x01);

        // Use INTEGER tag (0x02) instead of OCTET STRING (0x04)
        der.push(0x02); // Wrong tag!
        der.push(fake_key.len() as u8);
        der.extend_from_slice(&fake_key);

        let result = SecretKey::from_der(&mut der);
        assert!(result.is_err(), "Non-OCTET-STRING private key should be rejected");
    }

    #[test]
    #[cfg(feature = "rand")]
    fn secp256k1_valid_der_roundtrip() {
        // Generate a valid key and verify we can create a proper DER encoding that works
        let sk = SecretKey::generate();
        let sk_bytes = sk.to_bytes();

        // Build a minimal valid ECPrivateKey DER
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE

        let version_len = 3;
        let pk_len = 2 + 32; // OCTET STRING header + 32-byte key
        let inner_len = version_len + pk_len;
        der.push(inner_len as u8);

        // version INTEGER = 1
        der.push(0x02);
        der.push(0x01);
        der.push(0x01);

        // privateKey OCTET STRING
        der.push(0x04);
        der.push(32);
        der.extend_from_slice(&sk_bytes);

        let result = SecretKey::from_der(&mut der);
        assert!(result.is_ok(), "Valid DER-encoded key should be accepted");

        let decoded_sk = result.unwrap();
        assert_eq!(decoded_sk.to_bytes(), sk_bytes, "Decoded key should match original");
    }
}
