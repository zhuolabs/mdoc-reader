use crate::cbor_string_map_struct::cbor_string_map_struct;
use crate::{CoseSign1, TaggedCborBytes};
use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::{decode, encode, Decoder, Encoder};
use std::collections::BTreeMap;

pub const DEVICE_RESPONSE_STATUS_OK: u64 = 0;
pub const DEVICE_RESPONSE_STATUS_GENERAL_ERROR: u64 = 10;
pub const DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR: u64 = 11;
pub const DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR: u64 = 12;

pub type DocumentError = BTreeMap<String, i64>;
pub type ErrorItems = BTreeMap<String, i64>;
pub type Errors = BTreeMap<String, ErrorItems>;
pub type DeviceSignedItems = BTreeMap<String, ElementValue>;
pub type DeviceNameSpaces = BTreeMap<String, DeviceSignedItems>;
pub type IssuerNameSpaces = BTreeMap<String, Vec<TaggedCborBytes<IssuerSignedItem>>>;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceResponse {
        required {
            pub version: String => "version",
            pub status: u64 => "status",
        }
        optional {
            pub documents: Vec<MdocDocument> => "documents",
            pub document_errors: Vec<DocumentError> => "documentErrors",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MdocDocument {
        required {
            pub doc_type: String => "docType",
            pub issuer_signed: IssuerSigned => "issuerSigned",
            pub device_signed: DeviceSigned => "deviceSigned",
        }
        optional {
            pub errors: Errors => "errors",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssuerSigned {
        required {
            pub issuer_auth: CoseSign1 => "issuerAuth",
        }
        optional {
            pub name_spaces: IssuerNameSpaces => "nameSpaces",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssuerSignedItem {
        required {
            pub digest_id: u64 => "digestID",
            pub random: ByteVec => "random",
            pub element_identifier: String => "elementIdentifier",
            pub element_value: ElementValue => "elementValue",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceSigned {
        required {
            pub name_spaces: TaggedCborBytes<DeviceNameSpaces> => "nameSpaces",
            pub device_auth: DeviceAuth => "deviceAuth",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceAuth {
        required {
        }
        optional {
            pub device_signature: CoseSign1 => "deviceSignature",
            pub device_mac: ElementValue => "deviceMac",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementValue {
    encoded_cbor: Vec<u8>,
}

impl ElementValue {
    pub fn encoded_cbor(&self) -> &[u8] {
        &self.encoded_cbor
    }

    pub fn as_str(&self) -> Result<String> {
        let mut d = Decoder::new(&self.encoded_cbor);
        Ok(d.str()?.to_string())
    }

    pub fn as_bool(&self) -> Result<bool> {
        let mut d = Decoder::new(&self.encoded_cbor);
        Ok(d.bool()?)
    }

    pub fn as_u64(&self) -> Result<u64> {
        let mut d = Decoder::new(&self.encoded_cbor);
        Ok(d.u64()?)
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut d = Decoder::new(&self.encoded_cbor);
        Ok(d.bytes()?.to_vec())
    }
}

impl<C> encode::Encode<C> for ElementValue {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), encode::Error<W::Error>> {
        e.writer_mut()
            .write_all(&self.encoded_cbor)
            .map_err(encode::Error::write)?;
        Ok(())
    }
}

impl<'b, C> decode::Decode<'b, C> for ElementValue {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(Self {
            encoded_cbor: d.input()[start..end].to_vec(),
        })
    }
}


fn decode_string(items: &[TaggedCborBytes<IssuerSignedItem>], key: &str) -> Option<String> {
    find_element_value(items, key).and_then(|value| value.as_str().ok())
}

fn decode_bool(items: &[TaggedCborBytes<IssuerSignedItem>], key: &str) -> Option<bool> {
    find_element_value(items, key).and_then(|value| value.as_bool().ok())
}

fn decode_u64(items: &[TaggedCborBytes<IssuerSignedItem>], key: &str) -> Option<u64> {
    find_element_value(items, key).and_then(|value| value.as_u64().ok())
}

fn decode_bytes(items: &[TaggedCborBytes<IssuerSignedItem>], key: &str) -> Option<Vec<u8>> {
    find_element_value(items, key).and_then(|value| value.as_bytes().ok())
}


pub fn find_element_value<'a>(
    items: &'a [TaggedCborBytes<IssuerSignedItem>],
    key: &str,
) -> Option<&'a ElementValue> {
    items
        .iter()
        .find(|item| item.0.element_identifier == key)
        .map(|item| &item.0.element_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_card_response() {
        let response = DeviceResponse {
            version: "1.0".to_string(),
            status: DEVICE_RESPONSE_STATUS_OK,
            documents: Some(vec![MdocDocument {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                issuer_signed: IssuerSigned {
                    issuer_auth: dummy_cose_sign1(),
                    name_spaces: Some(BTreeMap::from([
                        (
                            "org.iso.18013.5.1".to_string(),
                            vec![
                                issuer_signed_item("family_name", string_value("Mustermann")),
                                issuer_signed_item("portrait", bytes_value(&[1, 2, 3, 4])),
                            ],
                        ),
                        (
                            "org.iso.18013.5.1.aamva".to_string(),
                            vec![
                                issuer_signed_item("age_over_20", bool_value(true)),
                                issuer_signed_item("age_in_years", u64_value(20)),
                            ],
                        ),
                    ])),
                },
                device_signed: DeviceSigned {
                    name_spaces: TaggedCborBytes(BTreeMap::new()),
                    device_auth: DeviceAuth {
                        device_signature: Some(dummy_cose_sign1()),
                        device_mac: None,
                    },
                },
                errors: None,
            }]),
            document_errors: None,
        };

        let encoded = minicbor::to_vec(&response).unwrap();
        let decoded: DeviceResponse = minicbor::decode(&encoded).unwrap();
        let signed_data = decoded.documents.as_ref().unwrap()[0]
            .issuer_signed
            .name_spaces
            .as_ref()
            .unwrap()
            .get("org.iso.18013.5.1")
            .unwrap();

        assert_eq!(decoded, response);
        assert_eq!(find_element_value(&signed_data, "family_name").unwrap().as_str().unwrap(), "Mustermann");
        assert_eq!(find_element_value(&signed_data, "portrait").unwrap().as_bytes().unwrap(), &[1, 2, 3, 4]);
    }

    fn issuer_signed_item(
        identifier: &str,
        element_value: ElementValue,
    ) -> TaggedCborBytes<IssuerSignedItem> {
        TaggedCborBytes(IssuerSignedItem {
            digest_id: 0,
            random: ByteVec::from(vec![0]),
            element_identifier: identifier.to_string(),
            element_value,
        })
    }

    fn dummy_cose_sign1() -> CoseSign1 {
        CoseSign1 {
            protected: crate::ProtectedHeaderMap(None),
            unprotected: crate::HeaderMap::default(),
            payload: None,
            signature: ByteVec::from(vec![0u8; 64]),
        }
    }

    fn string_value(value: &str) -> ElementValue {
        let mut e = Encoder::new(Vec::new());
        e.str(value).unwrap();
        ElementValue {
            encoded_cbor: e.into_writer(),
        }
    }

    fn bool_value(value: bool) -> ElementValue {
        let mut e = Encoder::new(Vec::new());
        e.bool(value).unwrap();
        ElementValue {
            encoded_cbor: e.into_writer(),
        }
    }

    fn u64_value(value: u64) -> ElementValue {
        let mut e = Encoder::new(Vec::new());
        e.u64(value).unwrap();
        ElementValue {
            encoded_cbor: e.into_writer(),
        }
    }

    fn bytes_value(value: &[u8]) -> ElementValue {
        let mut e = Encoder::new(Vec::new());
        e.bytes(value).unwrap();
        ElementValue {
            encoded_cbor: e.into_writer(),
        }
    }
}
