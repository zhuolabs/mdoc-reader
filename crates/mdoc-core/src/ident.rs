use crate::{CoseKeyPublic, TaggedCborBytes};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

pub fn ble_ident(esender_key: &TaggedCborBytes<CoseKeyPublic>) -> Result<[u8; 16]> {
    let ikm = minicbor::to_vec(esender_key)?;
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 16];
    hk.expand(b"BLEIdent", &mut out)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed for BLEIdent"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose_key::{Curve, KeyType};
    use hex::decode;
    use minicbor::bytes::ByteVec;

    #[test]
    fn ble_ident_vector() {
        let esender_key_raw = CoseKeyPublic {
            kty: KeyType::Ec2,
            crv: Curve::P256,
            x: ByteVec::from(
                decode("5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe").unwrap(),
            ),
            y: ByteVec::from(
                decode("b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67").unwrap(),
            ),
        };
        let esender_key: TaggedCborBytes<CoseKeyPublic> = TaggedCborBytes::from(&esender_key_raw);

        let ident = ble_ident(&esender_key).unwrap();
        assert_eq!(hex::encode(ident), "8da0b7a85919f05673054ea996bbd124");
    }
}
