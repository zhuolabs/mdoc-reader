use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

use crate::{HeaderMap, ProtectedHeaderMap};

pub const MAC0_CONTEXT: &str = "MAC0";

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseMac0 {
    #[n(0)]
    pub protected: ProtectedHeaderMap,
    #[n(1)]
    pub unprotected: HeaderMap,
    #[n(2)]
    pub payload: Option<ByteVec>,
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
