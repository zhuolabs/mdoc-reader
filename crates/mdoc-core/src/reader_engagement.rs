use anyhow::Result;
use minicbor::{Decode, Encode};
use ndef_rs::payload::ExternalPayload;
use ndef_rs::{NdefRecord, TNF};
use std::convert::TryFrom;

const READER_ENGAGEMENT_VERSION_1_0: &str = "1.0";
pub const READER_ENGAGEMENT_RECORD_TYPE: &[u8] = b"iso.org:18013:readerengagement";
pub const READER_ENGAGEMENT_ID: &[u8] = b"mdocreader";

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(map)]
pub struct ReaderEngagement {
    #[n(0)]
    pub version: String,
}

impl Default for ReaderEngagement {
    fn default() -> Self {
        ReaderEngagement {
            version: READER_ENGAGEMENT_VERSION_1_0.to_string(),
        }
    }
}

impl ReaderEngagement {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.version.is_empty(),
            "ReaderEngagement version is empty"
        );

        Ok(())
    }
}

impl TryFrom<&NdefRecord> for ReaderEngagement {
    type Error = anyhow::Error;

    fn try_from(record: &NdefRecord) -> Result<Self> {
        anyhow::ensure!(
            record.tnf() == TNF::External
                && record.record_type() == READER_ENGAGEMENT_RECORD_TYPE
                && record.id() == Some(READER_ENGAGEMENT_ID),
            "record is not iso.org:18013:readerengagement"
        );
        let engagement: ReaderEngagement = minicbor::decode(record.payload())
            .map_err(|e| anyhow::anyhow!("ReaderEngagement decode failed: {}", e))?;
        engagement.validate()?;
        Ok(engagement)
    }
}

impl TryFrom<&ReaderEngagement> for NdefRecord {
    type Error = anyhow::Error;

    fn try_from(value: &ReaderEngagement) -> Result<Self> {
        value.validate()?;
        let payload = minicbor::to_vec(value)
            .map_err(|e| anyhow::anyhow!("ReaderEngagement encode failed: {}", e))?;
        let raw = ExternalPayload::from_raw(READER_ENGAGEMENT_RECORD_TYPE.to_vec(), payload);

        NdefRecord::builder()
            .tnf(TNF::External)
            .id(READER_ENGAGEMENT_ID.to_vec())
            .payload(&raw)
            .build()
            .map_err(|e| anyhow::anyhow!("ReaderEngagement NDEF record build failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ndef_record() {
        let record: NdefRecord = (&ReaderEngagement::default()).try_into().unwrap();

        assert_eq!(record.tnf(), TNF::External);
        assert_eq!(record.record_type(), READER_ENGAGEMENT_RECORD_TYPE);
        assert_eq!(record.id(), Some(READER_ENGAGEMENT_ID));
    }
}
