use std::convert::TryFrom;

use crate::connection_handover_types::{CarrierPowerState, Error};

#[derive(Debug, Clone)]
pub struct AlternativeCarrier {
    pub cps: CarrierPowerState,
    pub carrier_data_reference: Vec<u8>,
    pub auxiliary_data_reference: Vec<Vec<u8>>,
}

impl AlternativeCarrier {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(self.cps.into());
        buf.push(self.carrier_data_reference.len() as u8);
        buf.extend_from_slice(&self.carrier_data_reference);
        buf.push(self.auxiliary_data_reference.len() as u8);

        for aux in &self.auxiliary_data_reference {
            buf.push(aux.len() as u8);
            buf.extend_from_slice(aux);
        }

        buf
    }

    pub fn parse(mut payload: &[u8]) -> Result<(Self, &[u8]), Error> {
        if payload.len() < 3 {
            return Err(Error::InvalidMessage);
        }

        let cps = CarrierPowerState::try_from(payload[0])?;
        payload = &payload[1..];

        let carrier_len = payload[0] as usize;
        payload = &payload[1..];
        if payload.len() < carrier_len + 1 {
            return Err(Error::InvalidMessage);
        }

        let carrier_data_reference = payload[..carrier_len].to_vec();
        payload = &payload[carrier_len..];

        let aux_count = payload[0] as usize;
        payload = &payload[1..];

        let mut auxiliary_data_reference = Vec::with_capacity(aux_count);
        for _ in 0..aux_count {
            let Some((&len, rest)) = payload.split_first() else {
                return Err(Error::InvalidMessage);
            };
            payload = rest;
            let len = len as usize;
            if payload.len() < len {
                return Err(Error::InvalidMessage);
            }
            auxiliary_data_reference.push(payload[..len].to_vec());
            payload = &payload[len..];
        }

        Ok((
            Self {
                cps,
                carrier_data_reference,
                auxiliary_data_reference,
            },
            payload,
        ))
    }
}
