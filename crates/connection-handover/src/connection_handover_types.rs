use std::convert::TryFrom;

use ndef_rs::NdefRecord;

#[derive(Debug)]
pub enum Error {
    InvalidMessage,
    InvalidHeader,
    InvalidEmbeddedMessage,
    CarrierNotFound,
    AuxiliaryNotFound,
    InvalidCps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierPowerState {
    Active,
    Activating,
    Inactive,
}

impl TryFrom<u8> for CarrierPowerState {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Active),
            0x02 => Ok(Self::Activating),
            0x03 => Ok(Self::Inactive),
            _ => Err(Error::InvalidCps),
        }
    }
}

impl From<CarrierPowerState> for u8 {
    fn from(value: CarrierPowerState) -> Self {
        match value {
            CarrierPowerState::Active => 0x01,
            CarrierPowerState::Activating => 0x02,
            CarrierPowerState::Inactive => 0x03,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CarrierRecord {
    pub(crate) cps: CarrierPowerState,
    pub(crate) carrier: NdefRecord,
    pub(crate) auxiliary: Vec<NdefRecord>,
}

impl CarrierRecord {
    pub(crate) fn find_auxiliary<'a, T, F>(&'a self, predicate: F) -> Option<T>
    where
        F: FnMut(&'a NdefRecord) -> Option<T>,
    {
        self.auxiliary.iter().find_map(predicate)
    }
}
