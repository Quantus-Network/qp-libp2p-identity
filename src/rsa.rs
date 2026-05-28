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

//! RSA keys.

use super::error::*;
use asn1_der::typed::{DerDecodable, DerEncodable, DerTypeView, Sequence};
use asn1_der::{Asn1DerError, Asn1DerErrorVariant, DerObject, Sink, VecBacking};
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use ring::signature::{self, RsaKeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256};
use std::{fmt, sync::Arc};
use zeroize::Zeroize;

/// An RSA keypair.
#[derive(Clone)]
pub struct Keypair(Arc<RsaKeyPair>);

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", self.0.public_key())
            .finish()
    }
}

impl Keypair {
    /// Decode an RSA keypair from a DER-encoded private key in PKCS#1 RSAPrivateKey
    /// format (i.e. unencrypted) as defined in [RFC3447].
    ///
    /// [RFC3447]: https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn try_decode_pkcs1(der: &mut [u8]) -> Result<Keypair, DecodingError> {
        let kp = RsaKeyPair::from_der(der)
            .map_err(|e| DecodingError::failed_to_parse("RSA DER PKCS#1 RSAPrivateKey", e))?;
        der.zeroize();
        Ok(Keypair(Arc::new(kp)))
    }

    /// Decode an RSA keypair from a DER-encoded private key in PKCS#8 PrivateKeyInfo
    /// format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    pub fn try_decode_pkcs8(der: &mut [u8]) -> Result<Keypair, DecodingError> {
        let kp = RsaKeyPair::from_pkcs8(der)
            .map_err(|e| DecodingError::failed_to_parse("RSA PKCS#8 PrivateKeyInfo", e))?;
        der.zeroize();
        Ok(Keypair(Arc::new(kp)))
    }

    /// Get the public key from the keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public_key().as_ref().to_vec())
    }

    /// Sign a message with this keypair.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut signature = vec![0; self.0.public_modulus_len()];
        let rng = SystemRandom::new();
        match self.0.sign(&RSA_PKCS1_SHA256, &rng, data, &mut signature) {
            Ok(()) => Ok(signature),
            Err(e) => Err(SigningError::new("RSA").source(e)),
        }
    }
}

/// An RSA public key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Verify an RSA signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let key = signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.0);
        key.verify(msg, sig).is_ok()
    }

    /// Encode the RSA public key in DER as a PKCS#1 RSAPublicKey structure,
    /// as defined in [RFC3447].
    ///
    /// [RFC3447]: https://tools.ietf.org/html/rfc3447#appendix-A.1.1
    pub fn encode_pkcs1(&self) -> Vec<u8> {
        // This is the encoding currently used in-memory, so it is trivial.
        self.0.clone()
    }

    /// Encode the RSA public key in DER as a X.509 SubjectPublicKeyInfo structure,
    /// as defined in [RFC5280].
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    pub fn encode_x509(&self) -> Vec<u8> {
        let spki = Asn1SubjectPublicKeyInfo {
            algorithmIdentifier: Asn1RsaEncryption {
                algorithm: Asn1OidRsaEncryption,
                parameters: (),
            },
            subjectPublicKey: Asn1SubjectPublicKey(self.clone()),
        };
        let mut buf = Vec::new();
        spki.encode(&mut buf)
            .map(|_| buf)
            .expect("RSA X.509 public key encoding failed.")
    }

    /// Decode an RSA public key from a DER-encoded X.509 SubjectPublicKeyInfo
    /// structure. See also `encode_x509`.
    pub fn try_decode_x509(pk: &[u8]) -> Result<PublicKey, DecodingError> {
        Asn1SubjectPublicKeyInfo::decode(pk)
            .map_err(|e| DecodingError::failed_to_parse("RSA X.509", e))
            .map(|spki| spki.subjectPublicKey.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(PKCS1): ")?;
        for byte in &self.0 {
            write!(f, "{byte:x}")?;
        }
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////
// DER encoding / decoding of public keys
//
// Primer: http://luca.ntop.org/Teaching/Appunti/asn1.html
// Playground: https://lapo.it/asn1js/

/// A raw ASN1 OID.
#[derive(Copy, Clone)]
struct Asn1RawOid<'a> {
    object: DerObject<'a>,
}

impl<'a> Asn1RawOid<'a> {
    /// The underlying OID as byte literal.
    pub(crate) fn oid(&self) -> &[u8] {
        self.object.value()
    }

    /// Writes an OID raw `value` as DER-object to `sink`.
    pub(crate) fn write<S: Sink>(value: &[u8], sink: &mut S) -> Result<(), Asn1DerError> {
        DerObject::write(Self::TAG, value.len(), &mut value.iter(), sink)
    }
}

impl<'a> DerTypeView<'a> for Asn1RawOid<'a> {
    const TAG: u8 = 6;

    fn object(&self) -> DerObject<'a> {
        self.object
    }
}

impl<'a> DerEncodable for Asn1RawOid<'a> {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        self.object.encode(sink)
    }
}

impl<'a> DerDecodable<'a> for Asn1RawOid<'a> {
    fn load(object: DerObject<'a>) -> Result<Self, Asn1DerError> {
        if object.tag() != Self::TAG {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "DER object tag is not the object identifier tag.",
            )));
        }

        Ok(Self { object })
    }
}

/// The ASN.1 OID for "rsaEncryption".
#[derive(Clone)]
struct Asn1OidRsaEncryption;

impl Asn1OidRsaEncryption {
    /// The DER encoding of the object identifier (OID) 'rsaEncryption' for
    /// RSA public keys defined for X.509 in [RFC-3279] and used in
    /// SubjectPublicKeyInfo structures defined in [RFC-5280].
    ///
    /// [RFC-3279]: https://tools.ietf.org/html/rfc3279#section-2.3.1
    /// [RFC-5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    const OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
}

impl DerEncodable for Asn1OidRsaEncryption {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        Asn1RawOid::write(&Self::OID, sink)
    }
}

impl DerDecodable<'_> for Asn1OidRsaEncryption {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        match Asn1RawOid::load(object)?.oid() {
            oid if oid == Self::OID => Ok(Self),
            _ => Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "DER object is not the 'rsaEncryption' identifier.",
            ))),
        }
    }
}

/// The ASN.1 AlgorithmIdentifier for "rsaEncryption".
struct Asn1RsaEncryption {
    algorithm: Asn1OidRsaEncryption,
    parameters: (),
}

impl DerEncodable for Asn1RsaEncryption {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let mut algorithm_buf = Vec::new();
        let algorithm = self.algorithm.der_object(VecBacking(&mut algorithm_buf))?;

        let mut parameters_buf = Vec::new();
        let parameters = self
            .parameters
            .der_object(VecBacking(&mut parameters_buf))?;

        Sequence::write(&[algorithm, parameters], sink)
    }
}

impl DerDecodable<'_> for Asn1RsaEncryption {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        let seq: Sequence = Sequence::load(object)?;

        Ok(Self {
            algorithm: seq.get_as(0)?,
            parameters: seq.get_as(1)?,
        })
    }
}

/// The ASN.1 SubjectPublicKey inside a SubjectPublicKeyInfo,
/// i.e. encoded as a DER BIT STRING.
struct Asn1SubjectPublicKey(PublicKey);

/// Maximum allowed size for an RSA public key in PKCS#1 DER format.
/// This library supports RSA keys from 2048 to 8192 bits (via ring's RSA_PKCS1_2048_8192_SHA256).
/// An 8192-bit RSA modulus is 1024 bytes, plus the public exponent and DER overhead.
/// We set a generous limit of 1200 bytes to accommodate the largest supported keys
/// while preventing denial-of-service through oversized allocations.
const MAX_RSA_PKCS1_DER_SIZE: usize = 1200;

impl DerEncodable for Asn1SubjectPublicKey {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let pk_der = &(self.0).0;
        let mut bit_string = Vec::with_capacity(pk_der.len() + 1);
        // The number of bits in pk_der is trivially always a multiple of 8,
        // so there are always 0 "unused bits" signaled by the first byte.
        bit_string.push(0u8);
        bit_string.extend(pk_der);
        DerObject::write(3, bit_string.len(), &mut bit_string.iter(), sink)?;
        Ok(())
    }
}

impl DerDecodable<'_> for Asn1SubjectPublicKey {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        if object.tag() != 3 {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "DER object tag is not the bit string tag.",
            )));
        }

        let value = object.value();

        // The BIT STRING must have at least one byte (the "unused bits" byte)
        // plus the actual key data
        if value.is_empty() {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key BIT STRING is empty.",
            )));
        }

        // Check the "unused bits" byte - for RSA keys this should be 0
        // (key length is always a multiple of 8 bits)
        if value[0] != 0 {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key BIT STRING has non-zero unused bits.",
            )));
        }

        // Check size bounds BEFORE allocating to prevent DoS via oversized inputs.
        // The key data is everything after the "unused bits" byte.
        let key_data_len = value.len() - 1;
        if key_data_len > MAX_RSA_PKCS1_DER_SIZE {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key exceeds maximum allowed size.",
            )));
        }

        // Validate that the inner data is a valid DER SEQUENCE (PKCS#1 RSAPublicKey structure)
        // before allocating. The first byte should be 0x30 (SEQUENCE tag).
        let key_data = &value[1..];
        if key_data.is_empty() || key_data[0] != 0x30 {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key is not a valid PKCS#1 RSAPublicKey SEQUENCE.",
            )));
        }

        // Parse as a DER object to validate the structure before allocating a Vec
        let inner_obj = DerObject::decode(key_data).map_err(|_| {
            Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key contains invalid DER encoding.",
            ))
        })?;

        // Verify it's a SEQUENCE with the expected structure (n INTEGER, e INTEGER)
        let seq = Sequence::load(inner_obj).map_err(|_| {
            Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key is not a valid SEQUENCE.",
            ))
        })?;

        // PKCS#1 RSAPublicKey has exactly 2 elements: modulus (n) and exponent (e)
        if seq.len() != 2 {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key SEQUENCE does not have exactly 2 elements.",
            )));
        }

        // Verify both elements are INTEGERs (tag 0x02)
        let n_obj = seq.get(0).map_err(|_| {
            Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "Failed to get RSA modulus from SEQUENCE.",
            ))
        })?;
        let e_obj = seq.get(1).map_err(|_| {
            Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "Failed to get RSA exponent from SEQUENCE.",
            ))
        })?;

        if n_obj.tag() != 2 || e_obj.tag() != 2 {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "RSA public key components are not INTEGERs.",
            )));
        }

        // Now that we've validated the structure, allocate the Vec
        let pk_der: Vec<u8> = key_data.to_vec();

        Ok(Self(PublicKey(pk_der)))
    }
}

/// ASN.1 SubjectPublicKeyInfo
#[allow(non_snake_case)]
struct Asn1SubjectPublicKeyInfo {
    algorithmIdentifier: Asn1RsaEncryption,
    subjectPublicKey: Asn1SubjectPublicKey,
}

impl DerEncodable for Asn1SubjectPublicKeyInfo {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let mut identifier_buf = Vec::new();
        let identifier = self
            .algorithmIdentifier
            .der_object(VecBacking(&mut identifier_buf))?;

        let mut key_buf = Vec::new();
        let key = self.subjectPublicKey.der_object(VecBacking(&mut key_buf))?;

        Sequence::write(&[identifier, key], sink)
    }
}

impl DerDecodable<'_> for Asn1SubjectPublicKeyInfo {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        let seq: Sequence = Sequence::load(object)?;

        Ok(Self {
            algorithmIdentifier: seq.get_as(0)?,
            subjectPublicKey: seq.get_as(1)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    const KEY1: &[u8] = include_bytes!("test/rsa-2048.pk8");
    const KEY2: &[u8] = include_bytes!("test/rsa-3072.pk8");
    const KEY3: &[u8] = include_bytes!("test/rsa-4096.pk8");

    #[derive(Clone, Debug)]
    struct SomeKeypair(Keypair);

    impl Arbitrary for SomeKeypair {
        fn arbitrary(g: &mut Gen) -> SomeKeypair {
            let mut key = g.choose(&[KEY1, KEY2, KEY3]).unwrap().to_vec();
            SomeKeypair(Keypair::try_decode_pkcs8(&mut key).unwrap())
        }
    }

    #[test]
    fn rsa_from_pkcs8() {
        assert!(Keypair::try_decode_pkcs8(&mut KEY1.to_vec()).is_ok());
        assert!(Keypair::try_decode_pkcs8(&mut KEY2.to_vec()).is_ok());
        assert!(Keypair::try_decode_pkcs8(&mut KEY3.to_vec()).is_ok());
    }

    #[test]
    fn rsa_x509_encode_decode() {
        fn prop(SomeKeypair(kp): SomeKeypair) -> Result<bool, String> {
            let pk = kp.public();
            PublicKey::try_decode_x509(&pk.encode_x509())
                .map_err(|e| e.to_string())
                .map(|pk2| pk2 == pk)
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn(_) -> _);
    }

    #[test]
    fn rsa_sign_verify() {
        fn prop(SomeKeypair(kp): SomeKeypair, msg: Vec<u8>) -> Result<bool, SigningError> {
            kp.sign(&msg).map(|s| kp.public().verify(&msg, &s))
        }
        QuickCheck::new()
            .tests(10)
            .quickcheck(prop as fn(_, _) -> _);
    }

    #[test]
    fn rsa_reject_oversized_public_key() {
        // Construct a malicious X.509 SubjectPublicKeyInfo with an oversized BIT STRING
        // This should be rejected before any large allocation occurs

        // RSA algorithm identifier: SEQUENCE { OID rsaEncryption, NULL }
        let alg_id: &[u8] = &[
            0x30, 0x0d, // SEQUENCE, length 13
            0x06, 0x09, // OID, length 9
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption OID
            0x05, 0x00, // NULL
        ];

        // Create a BIT STRING claiming to contain a huge key (but with minimal actual data)
        // BIT STRING tag = 0x03, then length encoding for > MAX_RSA_PKCS1_DER_SIZE
        // We'll use a length that exceeds the limit
        let oversized_len = MAX_RSA_PKCS1_DER_SIZE + 100;

        // Construct the BIT STRING with long-form length encoding
        let mut bit_string = vec![0x03]; // BIT STRING tag
        // Long-form length: 0x82 means 2 bytes follow for length
        bit_string.push(0x82);
        bit_string.push(((oversized_len >> 8) & 0xff) as u8);
        bit_string.push((oversized_len & 0xff) as u8);
        bit_string.push(0x00); // unused bits byte
        // Add minimal fake data (not a valid RSA key, but we should reject on size first)
        bit_string.extend(vec![0x30; oversized_len - 1]); // Pad with SEQUENCE tags

        // Build the full SPKI structure
        let mut spki = vec![0x30]; // SEQUENCE tag
        let inner_len = alg_id.len() + bit_string.len();
        // Long-form length for outer SEQUENCE
        spki.push(0x82);
        spki.push(((inner_len >> 8) & 0xff) as u8);
        spki.push((inner_len & 0xff) as u8);
        spki.extend_from_slice(alg_id);
        spki.extend_from_slice(&bit_string);

        let result = PublicKey::try_decode_x509(&spki);
        assert!(result.is_err(), "Oversized RSA public key should be rejected");
    }

    #[test]
    fn rsa_reject_invalid_inner_structure() {
        // Construct an X.509 SPKI with a BIT STRING that doesn't contain a valid PKCS#1 structure

        // RSA algorithm identifier
        let alg_id: &[u8] = &[
            0x30, 0x0d,
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
        ];

        // BIT STRING containing garbage instead of a valid RSA key
        let invalid_key: &[u8] = &[
            0x03, 0x05, // BIT STRING, length 5
            0x00,       // unused bits = 0
            0x01, 0x02, 0x03, 0x04, // garbage data (not starting with 0x30 SEQUENCE)
        ];

        let mut spki = vec![0x30]; // SEQUENCE tag
        let inner_len = alg_id.len() + invalid_key.len();
        spki.push(inner_len as u8);
        spki.extend_from_slice(alg_id);
        spki.extend_from_slice(invalid_key);

        let result = PublicKey::try_decode_x509(&spki);
        assert!(result.is_err(), "Invalid inner structure should be rejected");
    }

    #[test]
    fn rsa_reject_empty_bit_string() {
        // RSA algorithm identifier
        let alg_id: &[u8] = &[
            0x30, 0x0d,
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
        ];

        // Empty BIT STRING
        let empty_key: &[u8] = &[0x03, 0x00]; // BIT STRING, length 0

        let mut spki = vec![0x30];
        let inner_len = alg_id.len() + empty_key.len();
        spki.push(inner_len as u8);
        spki.extend_from_slice(alg_id);
        spki.extend_from_slice(empty_key);

        let result = PublicKey::try_decode_x509(&spki);
        assert!(result.is_err(), "Empty BIT STRING should be rejected");
    }
}
