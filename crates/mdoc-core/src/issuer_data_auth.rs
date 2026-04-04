use crate::{MdocDocument, MobileSecurityObject, TaggedCborBytes};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct IssuerDataAuthContext {
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VerifiedMso {
    pub mso: MobileSecurityObject,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerDataAuthError {
    MissingIssuerAuthPayload,
    InvalidIssuerAuthPayload,
    DocTypeMismatch {
        document_doc_type: String,
        mso_doc_type: String,
    },
    InvalidValidityTimeFormat {
        field: &'static str,
    },
    ValidityTimeNotUtc {
        field: &'static str,
    },
    InvalidValidityRange {
        valid_from: String,
        valid_until: String,
    },
    NotYetValid {
        now: DateTime<Utc>,
        valid_from: DateTime<Utc>,
    },
    Expired {
        now: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    UnsupportedDigestAlgorithm {
        algorithm: String,
    },
    MissingNamespaceDigests {
        namespace: String,
    },
    MissingDigestId {
        namespace: String,
        digest_id: u64,
    },
    DigestMismatch {
        namespace: String,
        digest_id: u64,
    },
    CborEncodeFailure,
}

impl Display for IssuerDataAuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingIssuerAuthPayload => write!(f, "issuerAuth payload is missing"),
            Self::InvalidIssuerAuthPayload => write!(f, "issuerAuth payload is not a valid MSO"),
            Self::DocTypeMismatch {
                document_doc_type,
                mso_doc_type,
            } => write!(
                f,
                "docType mismatch: document={}, mso={}",
                document_doc_type, mso_doc_type
            ),
            Self::InvalidValidityTimeFormat { field } => {
                write!(f, "{} is not a valid RFC3339 datetime", field)
            }
            Self::ValidityTimeNotUtc { field } => write!(f, "{} must be UTC", field),
            Self::InvalidValidityRange {
                valid_from,
                valid_until,
            } => write!(
                f,
                "invalid validity range: validFrom={} > validUntil={}",
                valid_from, valid_until
            ),
            Self::NotYetValid { now, valid_from } => {
                write!(f, "document is not yet valid: now={} < {}", now, valid_from)
            }
            Self::Expired { now, valid_until } => {
                write!(f, "document is expired: now={} > {}", now, valid_until)
            }
            Self::UnsupportedDigestAlgorithm { algorithm } => {
                write!(f, "unsupported digest algorithm: {}", algorithm)
            }
            Self::MissingNamespaceDigests { namespace } => {
                write!(f, "valueDigests missing namespace: {}", namespace)
            }
            Self::MissingDigestId {
                namespace,
                digest_id,
            } => write!(
                f,
                "valueDigests missing digestID {} for namespace {}",
                digest_id, namespace
            ),
            Self::DigestMismatch {
                namespace,
                digest_id,
            } => write!(
                f,
                "digest mismatch for namespace {} digestID {}",
                namespace, digest_id
            ),
            Self::CborEncodeFailure => write!(f, "failed to encode tagged issuer signed item"),
        }
    }
}

impl std::error::Error for IssuerDataAuthError {}

pub fn verify_issuer_data_auth(
    doc: &MdocDocument,
    ctx: &IssuerDataAuthContext,
) -> Result<VerifiedMso, IssuerDataAuthError> {
    let payload = doc
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(IssuerDataAuthError::MissingIssuerAuthPayload)?;

    let mso: MobileSecurityObject = minicbor::decode(payload.as_slice())
        .map_err(|_| IssuerDataAuthError::InvalidIssuerAuthPayload)?;

    if doc.doc_type != mso.doc_type {
        return Err(IssuerDataAuthError::DocTypeMismatch {
            document_doc_type: doc.doc_type.clone(),
            mso_doc_type: mso.doc_type.clone(),
        });
    }

    let valid_from = parse_utc_datetime_strict("validFrom", &mso.validity_info.valid_from)?;
    let valid_until = parse_utc_datetime_strict("validUntil", &mso.validity_info.valid_until)?;

    if valid_from > valid_until {
        return Err(IssuerDataAuthError::InvalidValidityRange {
            valid_from: mso.validity_info.valid_from.clone(),
            valid_until: mso.validity_info.valid_until.clone(),
        });
    }

    if ctx.now < valid_from {
        return Err(IssuerDataAuthError::NotYetValid {
            now: ctx.now,
            valid_from,
        });
    }

    if ctx.now > valid_until {
        return Err(IssuerDataAuthError::Expired {
            now: ctx.now,
            valid_until,
        });
    }

    if mso.digest_algorithm != "SHA-256" {
        return Err(IssuerDataAuthError::UnsupportedDigestAlgorithm {
            algorithm: mso.digest_algorithm.clone(),
        });
    }

    if let Some(name_spaces) = &doc.issuer_signed.name_spaces {
        for (namespace, items) in name_spaces {
            let namespace_digests = mso.value_digests.get(namespace).ok_or_else(|| {
                IssuerDataAuthError::MissingNamespaceDigests {
                    namespace: namespace.clone(),
                }
            })?;

            for TaggedCborBytes(item) in items {
                let tagged_cbor_bytes = minicbor::to_vec(TaggedCborBytes(item.clone()))
                    .map_err(|_| IssuerDataAuthError::CborEncodeFailure)?;
                let digest = Sha256::digest(tagged_cbor_bytes);

                let expected = namespace_digests.get(&item.digest_id).ok_or_else(|| {
                    IssuerDataAuthError::MissingDigestId {
                        namespace: namespace.clone(),
                        digest_id: item.digest_id,
                    }
                })?;

                if digest.as_slice() != expected.as_slice() {
                    return Err(IssuerDataAuthError::DigestMismatch {
                        namespace: namespace.clone(),
                        digest_id: item.digest_id,
                    });
                }
            }
        }
    }

    Ok(VerifiedMso {
        mso,
        valid_from,
        valid_until,
    })
}

fn parse_utc_datetime_strict(
    field: &'static str,
    input: &str,
) -> Result<DateTime<Utc>, IssuerDataAuthError> {
    let dt = DateTime::parse_from_rfc3339(input)
        .map_err(|_| IssuerDataAuthError::InvalidValidityTimeFormat { field })?;

    if dt.offset().local_minus_utc() != 0 {
        return Err(IssuerDataAuthError::ValidityTimeNotUtc { field });
    }

    Ok(dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose_key::{Curve, KeyType};
    use crate::device_response::{DeviceAuth, DeviceSigned, IssuerSigned};
    use crate::{
        CoseKeyPublic, CoseSign1, DeviceKeyInfo, HeaderMap, IssuerSignedItem, MdocDocument,
        ProtectedHeaderMap, ValidityInfo,
    };
    use minicbor::bytes::ByteVec;
    use std::collections::BTreeMap;

    #[test]
    fn verify_success() {
        let now = DateTime::parse_from_rfc3339("2026-01-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let item = issuer_item(7, "family_name", "Doe");
        let doc = document_with_item(
            item.clone(),
            "SHA-256",
            BTreeMap::from([(7_u64, ByteVec::from(digest_for_item(&item)))]),
            "2026-01-01T00:00:00Z",
            "2026-12-31T23:59:59Z",
        );

        let result = verify_issuer_data_auth(&doc, &IssuerDataAuthContext { now }).unwrap();
        assert_eq!(result.valid_from, parse_utc("2026-01-01T00:00:00Z"));
        assert_eq!(result.valid_until, parse_utc("2026-12-31T23:59:59Z"));
    }

    #[test]
    fn reject_non_utc_validity_time() {
        let now = parse_utc("2026-01-01T12:00:00Z");
        let item = issuer_item(1, "family_name", "Doe");
        let doc = document_with_item(
            item.clone(),
            "SHA-256",
            BTreeMap::from([(1_u64, ByteVec::from(digest_for_item(&item)))]),
            "2026-01-01T09:00:00+09:00",
            "2026-12-31T23:59:59Z",
        );

        let err = verify_issuer_data_auth(&doc, &IssuerDataAuthContext { now }).unwrap_err();
        assert_eq!(
            err,
            IssuerDataAuthError::ValidityTimeNotUtc { field: "validFrom" }
        );
    }

    #[test]
    fn reject_digest_mismatch() {
        let now = parse_utc("2026-01-01T12:00:00Z");
        let item = issuer_item(2, "family_name", "Doe");
        let doc = document_with_item(
            item,
            "SHA-256",
            BTreeMap::from([(2_u64, ByteVec::from(vec![0_u8; 32]))]),
            "2026-01-01T00:00:00Z",
            "2026-12-31T23:59:59Z",
        );

        let err = verify_issuer_data_auth(&doc, &IssuerDataAuthContext { now }).unwrap_err();
        assert_eq!(
            err,
            IssuerDataAuthError::DigestMismatch {
                namespace: "org.iso.18013.5.1".to_string(),
                digest_id: 2,
            }
        );
    }

    fn parse_utc(input: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(input)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn digest_for_item(item: &TaggedCborBytes<IssuerSignedItem>) -> Vec<u8> {
        let bytes = minicbor::to_vec(item).unwrap();
        Sha256::digest(bytes).to_vec()
    }

    fn issuer_item(digest_id: u64, key: &str, value: &str) -> TaggedCborBytes<IssuerSignedItem> {
        TaggedCborBytes(IssuerSignedItem {
            digest_id,
            random: ByteVec::from(vec![1_u8; 16]),
            element_identifier: key.to_string(),
            element_value: crate::ElementValue::from_string(value),
        })
    }

    fn document_with_item(
        item: TaggedCborBytes<IssuerSignedItem>,
        digest_algorithm: &str,
        digest_ids: BTreeMap<u64, ByteVec>,
        valid_from: &str,
        valid_until: &str,
    ) -> MdocDocument {
        let namespace = "org.iso.18013.5.1".to_string();
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: digest_algorithm.to_string(),
            value_digests: BTreeMap::from([(namespace.clone(), digest_ids)]),
            device_key_info: DeviceKeyInfo {
                device_key: CoseKeyPublic {
                    kty: KeyType::Ec2,
                    crv: Curve::P256,
                    x: ByteVec::from(vec![1_u8; 32]),
                    y: ByteVec::from(vec![2_u8; 32]),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: "2025-01-01T00:00:00Z".to_string(),
                valid_from: valid_from.to_string(),
                valid_until: valid_until.to_string(),
                expected_update: None,
            },
            status: None,
        };

        MdocDocument {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            issuer_signed: IssuerSigned {
                issuer_auth: CoseSign1 {
                    protected: ProtectedHeaderMap(None),
                    unprotected: HeaderMap::default(),
                    payload: Some(ByteVec::from(minicbor::to_vec(&mso).unwrap())),
                    signature: ByteVec::from(vec![0_u8; 64]),
                },
                name_spaces: Some(BTreeMap::from([(namespace, vec![item])])),
            },
            device_signed: DeviceSigned {
                name_spaces: TaggedCborBytes(BTreeMap::new()),
                device_auth: DeviceAuth {
                    device_signature: None,
                    device_mac: None,
                },
            },
            errors: None,
        }
    }
}
