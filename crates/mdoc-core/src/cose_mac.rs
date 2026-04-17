use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

use crate::cose_sign::CoseDecodePayload;
use crate::{CborAny, CborBytes, HeaderMap, ProtectedHeaderMap};

pub const MAC0_CONTEXT: &str = "MAC0";

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseMac0<T = CborAny>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    #[n(0)]
    pub protected: ProtectedHeaderMap,
    #[n(1)]
    pub unprotected: HeaderMap,
    #[n(2)]
    pub payload: Option<CborBytes<T>>,
    #[n(3)]
    pub tag: ByteVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct MacStructure {
    #[n(0)]
    pub context: String,
    #[n(1)]
    pub body_protected: ByteVec,
    #[n(2)]
    pub external_aad: ByteVec,
    #[n(3)]
    pub payload: ByteVec,
}

impl<T> CoseDecodePayload<T> for CoseMac0<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn decode_payload(&self) -> Result<T>
    where
        for<'a> T: Decode<'a, ()>,
    {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Mac0 payload is missing"))?;
        Ok(payload.decode()?)
    }
}
