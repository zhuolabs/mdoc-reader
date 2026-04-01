use crate::{CoseKeyPublic, TaggedCborBytes};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

pub fn ble_ident(esender_key: &CoseKeyPublic) -> Result<[u8; 16]> {
    let ikm = minicbor::to_vec(TaggedCborBytes(esender_key.clone()))?;
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 16];
    hk.expand(b"BLEIdent", &mut out)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed for BLEIdent"))?;
    Ok(out)
}
