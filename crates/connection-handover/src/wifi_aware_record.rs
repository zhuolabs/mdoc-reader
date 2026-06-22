use anyhow::{Result, bail, ensure};
use ndef_rs::payload::MimePayload;
use ndef_rs::{NdefRecord, TNF};
use std::convert::TryFrom;

pub const WIFI_AWARE_MIME_TYPE: &str = "application/vnd.wfa.nan";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WifiAwareRecord {
    pub service_name: Option<String>,
    pub pass_phrase: Option<String>,
    pub channel_info: Option<WifiAwareChannelInfo>,
    pub cipher_suite: Option<u8>,
    pub raw_attributes: Vec<WifiAwareAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiAwareChannelInfo {
    pub operating_class: u8,
    pub channel_number: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiAwareAttribute {
    pub attribute_id: u8,
    pub data: Vec<u8>,
}

const ATTR_SERVICE_NAME: u8 = 0x01;
const ATTR_PASS_PHRASE: u8 = 0x02;
const ATTR_CHANNEL_INFO: u8 = 0x03;
const ATTR_CIPHER_SUITE: u8 = 0x04;

impl TryFrom<&NdefRecord> for WifiAwareRecord {
    type Error = anyhow::Error;

    fn try_from(record: &NdefRecord) -> Result<Self> {
        if record.tnf() != TNF::MimeMedia || record.record_type() != WIFI_AWARE_MIME_TYPE.as_bytes()
        {
            bail!("record is not application/vnd.wfa.nan");
        }

        let mut parsed = Self::default();
        let mut cursor = 0usize;
        let payload = record.payload();
        while cursor < payload.len() {
            ensure!(
                cursor + 3 <= payload.len(),
                "Wi-Fi Aware attribute header exceeds payload length"
            );
            let attribute_id = payload[cursor];
            let len = u16::from_be_bytes([payload[cursor + 1], payload[cursor + 2]]) as usize;
            cursor += 3;
            ensure!(
                cursor + len <= payload.len(),
                "Wi-Fi Aware attribute exceeds payload length"
            );
            let data = payload[cursor..cursor + len].to_vec();
            cursor += len;

            match attribute_id {
                ATTR_SERVICE_NAME => parsed.service_name = Some(String::from_utf8(data)?),
                ATTR_PASS_PHRASE => parsed.pass_phrase = Some(String::from_utf8(data)?),
                ATTR_CHANNEL_INFO => {
                    ensure!(data.len() == 2, "Wi-Fi Aware channel info must be 2 bytes");
                    parsed.channel_info = Some(WifiAwareChannelInfo {
                        operating_class: data[0],
                        channel_number: data[1],
                    });
                }
                ATTR_CIPHER_SUITE => {
                    ensure!(data.len() == 1, "Wi-Fi Aware cipher suite must be 1 byte");
                    parsed.cipher_suite = Some(data[0]);
                }
                _ => parsed
                    .raw_attributes
                    .push(WifiAwareAttribute { attribute_id, data }),
            }
        }

        Ok(parsed)
    }
}

impl TryFrom<&WifiAwareRecord> for NdefRecord {
    type Error = anyhow::Error;

    fn try_from(value: &WifiAwareRecord) -> Result<Self> {
        let mut payload = Vec::new();
        if let Some(service_name) = &value.service_name {
            encode_attribute(&mut payload, ATTR_SERVICE_NAME, service_name.as_bytes())?;
        }
        if let Some(pass_phrase) = &value.pass_phrase {
            encode_attribute(&mut payload, ATTR_PASS_PHRASE, pass_phrase.as_bytes())?;
        }
        if let Some(channel_info) = &value.channel_info {
            encode_attribute(
                &mut payload,
                ATTR_CHANNEL_INFO,
                &[channel_info.operating_class, channel_info.channel_number],
            )?;
        }
        if let Some(cipher_suite) = value.cipher_suite {
            encode_attribute(&mut payload, ATTR_CIPHER_SUITE, &[cipher_suite])?;
        }
        for attr in &value.raw_attributes {
            encode_attribute(&mut payload, attr.attribute_id, &attr.data)?;
        }

        let raw = MimePayload::from_mime(
            WIFI_AWARE_MIME_TYPE
                .parse()
                .expect("Wi-Fi Aware MIME type must be valid"),
            payload,
        );
        Ok(NdefRecord::builder()
            .tnf(TNF::MimeMedia)
            .payload(&raw)
            .build()?)
    }
}

fn encode_attribute(payload: &mut Vec<u8>, attribute_id: u8, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() <= u16::MAX as usize,
        "Wi-Fi Aware attribute too large: {} bytes",
        data.len()
    );
    payload.push(attribute_id);
    payload.extend_from_slice(&(data.len() as u16).to_be_bytes());
    payload.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_wifi_aware_record() {
        let record = WifiAwareRecord {
            service_name: Some("94AB45CDBDEF675162183B12AC35EFAA".to_string()),
            pass_phrase: Some("test-passphrase".to_string()),
            channel_info: Some(WifiAwareChannelInfo {
                operating_class: 81,
                channel_number: 6,
            }),
            cipher_suite: Some(1),
            raw_attributes: vec![WifiAwareAttribute {
                attribute_id: 0x80,
                data: vec![1, 2, 3],
            }],
        };

        let ndef: NdefRecord = (&record).try_into().unwrap();
        let parsed: WifiAwareRecord = (&ndef).try_into().unwrap();

        assert_eq!(parsed, record);
    }
}
