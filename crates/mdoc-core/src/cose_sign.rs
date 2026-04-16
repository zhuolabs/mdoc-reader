use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier;

use crate::{CborAny, CborBytes, X5Chain};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseSign1<T = CborAny>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    #[n(0)]
    pub protected: CborBytes<HeaderMap>,
    #[n(1)]
    pub unprotected: HeaderMap,
    #[n(2)]
    pub payload: Option<CborBytes<T>>,
    #[n(3)]
    pub signature: ByteVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
struct SigStructureSignature1 {
    #[n(0)]
    pub context: String,
    #[n(1)]
    pub body_protected: ByteVec,
    #[n(2)]
    pub external_aad: ByteVec,
    #[n(3)]
    pub payload: ByteVec,
}

#[derive(Debug, Clone, Decode, PartialEq, Eq, Encode, Default)]
#[cbor(map)]
pub struct HeaderMap {
    #[n(1)]
    pub alg: Option<CoseAlg>,
    #[n(33)]
    pub x5chain: Option<X5Chain>,
}

pub type ProtectedHeaderMap = CborBytes<HeaderMap>;

impl HeaderMap {
    pub fn document_signer_cert(&self) -> Option<&x509_cert::Certificate> {
        self.x5chain
            .as_ref()
            .and_then(|chain| chain.as_slice().first())
    }

    pub fn intermediate_certs(&self) -> &[x509_cert::Certificate] {
        self.x5chain
            .as_deref()
            .map(|chain| chain.get(1..).unwrap_or(&[]))
            .unwrap_or(&[])
    }
}

#[derive(Decode, Debug, Encode, PartialEq, Eq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum CoseAlg {
    #[n(-3)]
    A128KW,
    #[n(-5)]
    A256KW,
    #[n(-29)]
    ECDHESA128KW,
    #[n(-9)]
    ES256P256,
    #[n(-7)]
    ES256,
    #[n(-19)]
    ED25519,
    #[n(-46)]
    HSSLMS,
    #[n(4)]
    HMAC25664,
    #[n(5)]
    HMAC256256,
}

impl<T> CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    pub fn decode_payload_cbor(&self) -> Result<T>
    where
        for<'a> T: Decode<'a, ()>,
    {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 payload is missing"))?;
        Ok(payload.decode()?)
    }

    pub fn resolved_alg(&self) -> Result<CoseAlg> {
        self.protected
            .decode()
            .map_err(|_| anyhow::anyhow!("protected header must be bstr.cbor header_map"))?
            .alg
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 algorithm is missing from protected header"))
    }

    pub fn resolved_document_signer_cert(&self) -> Result<Option<&x509_cert::Certificate>> {
        Ok(self.unprotected.document_signer_cert())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey, external_aad: &[u8]) -> Result<()> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 payload is missing"))?;
        self.verify_detached_payload(verifying_key, external_aad, payload.raw_cbor_bytes())
    }

    pub fn verify_with_certificate(
        &self,
        certificate: &x509_cert::Certificate,
        external_aad: &[u8],
    ) -> Result<()> {
        let sec1_bytes = certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("certificate public key is not byte-aligned"))?;
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_bytes)
            .map_err(|_| anyhow::anyhow!("certificate public key is not a valid P-256 key"))?;
        self.verify(&verifying_key, external_aad)
    }

    pub fn verify_detached_payload(
        &self,
        verifying_key: &VerifyingKey,
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        match self.resolved_alg()? {
            CoseAlg::ES256 | CoseAlg::ES256P256 => {
                let sig_structure = minicbor::to_vec(SigStructureSignature1 {
                    context: "Signature1".to_string(),
                    body_protected: ByteVec::from(self.protected.raw_cbor_bytes().to_vec()),
                    external_aad: ByteVec::from(external_aad.to_vec()),
                    payload: ByteVec::from(payload.to_vec()),
                })?;
                let signature = p256::ecdsa::Signature::from_slice(self.signature.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid ES256 signature bytes"))?;
                verifying_key
                    .verify(&sig_structure, &signature)
                    .map_err(|_| anyhow::anyhow!("COSE_Sign1 signature verification failed"))
            }
            alg => anyhow::bail!("unsupported COSE algorithm for signature verification: {alg:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::Encoder;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    #[test]
    fn protected_header_map_roundtrips_non_empty_bstr() {
        let protected = CborBytes::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let encoded = minicbor::to_vec(&protected).unwrap();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, protected);
    }

    #[test]
    fn protected_header_map_decodes_inner_header_map() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0xA0]).unwrap();
        let encoded = e.into_writer();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded.decode().unwrap(), HeaderMap::default());
    }

    #[test]
    fn protected_header_map_allows_later_validation_of_non_map_cbor() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0x01]).unwrap();
        let encoded = e.into_writer();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert!(decoded.decode().is_err());
    }

    #[test]
    fn decode_payload_cbor_decodes_payload() {
        let sign1 = CoseSign1::<String> {
            protected: CborBytes::from(&HeaderMap::default()),
            unprotected: HeaderMap::default(),
            payload: Some(CborBytes::from(&"hello".to_string())),
            signature: ByteVec::from(vec![0; 64]),
        };

        let payload = sign1.decode_payload_cbor().unwrap();
        assert_eq!(payload, "hello");
    }

    #[test]
    fn decode_payload_cbor_rejects_missing_payload() {
        let sign1 = CoseSign1::<String> {
            protected: CborBytes::from(&HeaderMap::default()),
            unprotected: HeaderMap::default(),
            payload: None,
            signature: ByteVec::from(vec![0; 64]),
        };

        let result = sign1.decode_payload_cbor();
        assert!(result.is_err());
    }

    #[test]
    fn sig_structure_signature1_roundtrip() {
        let sig_structure = SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(Vec::<u8>::new()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(b"payload".to_vec()),
        };
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let decoded: SigStructureSignature1 = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, sig_structure);
        assert_eq!(decoded.context, "Signature1");
        assert_eq!(decoded.external_aad.as_slice(), b"");
    }

    #[test]
    fn sig_structure_signature1_encoding_matches_expected() {
        let sig_structure = SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(Vec::<u8>::new()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(b"\x01\x02\x03".to_vec()),
        };
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x40, 0x40,
            0x43, 0x01, 0x02, 0x03,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn sig_structure_signature1_builds_signature_input() {
        let payload = b"\xAA\xBB";
        let encoded = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(
                CborBytes::from(&HeaderMap::default())
                    .raw_cbor_bytes()
                    .to_vec(),
            ),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(payload.to_vec()),
        })
        .unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x41, 0xA0,
            0x40, 0x42, 0xAA, 0xBB,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn verify_signature_input_uses_payload() {
        let sign1 = CoseSign1::<CborAny> {
            protected: CborBytes::from(&HeaderMap::default()),
            unprotected: HeaderMap::default(),
            payload: Some(CborBytes::from_raw_bytes(vec![0x01, 0x02])),
            signature: ByteVec::from(vec![0; 64]),
        };
        let encoded = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(sign1.protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(sign1.payload.as_ref().unwrap().raw_cbor_bytes().to_vec()),
        })
        .unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x41, 0xA0,
            0x40, 0x42, 0x01, 0x02,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn resolved_alg_uses_protected_only() {
        let sign1 = CoseSign1::<CborAny> {
            protected: CborBytes::from(&HeaderMap {
                alg: Some(CoseAlg::ES256),
                x5chain: None,
            }),
            unprotected: HeaderMap {
                alg: Some(CoseAlg::ED25519),
                x5chain: None,
            },
            payload: Some(CborBytes::from_raw_bytes(vec![0x01])),
            signature: ByteVec::from(vec![0; 64]),
        };

        assert_eq!(sign1.resolved_alg().unwrap(), CoseAlg::ES256);
    }

    #[test]
    fn verify_signature_with_public_key_accepts_valid_es256_signature() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let payload = CborBytes::from_raw_bytes(vec![0x01, 0x02, 0x03]);
        let protected = CborBytes::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let sig_structure = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(payload.raw_cbor_bytes().to_vec()),
        })
        .unwrap();
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
        let sign1 = CoseSign1::<CborAny> {
            protected,
            unprotected: HeaderMap::default(),
            payload: Some(payload),
            signature: ByteVec::from(signature.to_bytes().to_vec()),
        };
        let public_key = p256::PublicKey::from_sec1_bytes(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        sign1.verify(&(&public_key).into(), b"").unwrap();
    }

    #[test]
    fn verify_signature_with_public_key_detached_accepts_valid_es256_signature() {
        let signing_key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let detached_payload = vec![0x04, 0x05, 0x06];
        let protected = CborBytes::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let sig_structure = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(detached_payload.clone()),
        })
        .unwrap();
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
        let sign1 = CoseSign1::<CborAny> {
            protected,
            unprotected: HeaderMap::default(),
            payload: None,
            signature: ByteVec::from(signature.to_bytes().to_vec()),
        };
        let public_key = p256::PublicKey::from_sec1_bytes(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();

        sign1
            .verify_detached_payload(&(&public_key).into(), b"", &detached_payload)
            .unwrap();
    }
}
