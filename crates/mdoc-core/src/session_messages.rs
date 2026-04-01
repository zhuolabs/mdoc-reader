use crate::cbor_string_map_struct::cbor_string_map_struct;
use crate::{CoseKeyPublic, TaggedCborBytes};
use minicbor::bytes::ByteVec;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SessionEstablishment {
        required {
            pub e_reader_key: TaggedCborBytes<CoseKeyPublic> => "eReaderKey",
            pub data: ByteVec => "data",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct SessionData {
        required {
        }
        optional {
            pub data: ByteVec => "data",
            pub status: u64 => "status",
        }
    }
}
