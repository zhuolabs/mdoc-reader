use minicbor::{Decode, Encode};

use crate::IdentifierList;

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(map)]
pub struct CborWebToken {
    #[n(2)]
    pub uri: Option<String>,
    #[n(4)]
    pub exp: u64,
    #[n(6)]
    pub iat: Option<u64>,
    #[n(65530)]
    pub identifier_list: IdentifierList,
    #[n(65534)]
    pub ttl: Option<u64>,
}
