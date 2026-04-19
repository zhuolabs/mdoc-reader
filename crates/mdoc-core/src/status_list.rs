use crate::Certificate;
use crate::URI;
use crate::cbor_string_map_struct::cbor_string_map_struct;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StatusListInfo {
        required {
            pub idx: u64 => "idx",
            pub uri: URI => "uri",
        }
        optional {
            pub certificate: Certificate => "certificate",
        }
    }
}
