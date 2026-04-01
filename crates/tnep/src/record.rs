use crate::{Error, Result};
use ndef_rs::{NdefRecord, TNF};

/// Parsed Service Parameter Record ("Ts")
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceParameterRecord {
    pub(crate) service_name: String,
    pub(crate) version: u8,
    pub(crate) communication_mode: CommunicationMode,
    pub(crate) wt_int: u8,
    pub(crate) n_wait: u8,
    pub(crate) max_ndef_size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommunicationMode {
    SingleResponse,
    WaitForRelease,
}

impl ServiceParameterRecord {
    pub fn from_record(record: &NdefRecord) -> Result<Self> {
        if record.tnf() != TNF::WellKnown || record.record_type() != b"Tp" {
            return Err(Error::invalid_message());
        }

        let payload = record.payload();
        if payload.len() < 7 {
            return Err(Error::invalid_message());
        }

        let version = payload[0];
        let name_len = payload[1] as usize;
        if payload.len() < name_len + 7 {
            return Err(Error::invalid_message());
        }

        let service_name = std::str::from_utf8(&payload[2..2 + name_len])
            .map_err(|_| Error::invalid_message())?
            .to_owned();

        let communication_mode = match payload[2 + name_len] {
            0x00 => CommunicationMode::SingleResponse,
            0x01 => CommunicationMode::WaitForRelease,
            _ => return Err(Error::invalid_message()),
        };
        let wt_int = payload[3 + name_len];
        let n_wait = payload[4 + name_len];
        let max_ndef_size = u16::from_be_bytes([payload[5 + name_len], payload[6 + name_len]]);

        Ok(Self {
            service_name,
            version,
            communication_mode,
            wt_int,
            n_wait,
            max_ndef_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::parse_service_parameters;

    use super::*;
    use ndef_rs::NdefMessage;

    #[test]
    fn parses_tp_record_from_real_initial_msg() {
        let initial_msg_bytes = vec![
            0xD1, 0x02, 0x1A, 0x54, 0x70, 0x10, 0x13, 0x75, 0x72, 0x6E, 0x3A, 0x6E, 0x66, 0x63,
            0x3A, 0x73, 0x6E, 0x3A, 0x68, 0x61, 0x6E, 0x64, 0x6F, 0x76, 0x65, 0x72, 0x00, 0x14,
            0x0F, 0x08, 0x00,
        ];
        let msg = NdefMessage::decode(&initial_msg_bytes).expect("valid ndef");

        let services = parse_service_parameters(&msg);
        assert_eq!(services.len(), 1);

        let service = &services[0];
        assert_eq!(service.service_name, "urn:nfc:sn:handover");
        assert_eq!(service.version, 0x10);
        assert_eq!(
            service.communication_mode,
            CommunicationMode::SingleResponse
        );
        assert_eq!(service.wt_int, 0x14);
        assert_eq!(service.n_wait, 0x0F);
        assert_eq!(service.max_ndef_size, 0x0800);
    }
}
