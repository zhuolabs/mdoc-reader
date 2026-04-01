mod alternative_carrier;
mod ble_oob_record;
mod connection_handover;
mod connection_handover_types;

pub use ble_oob_record::{
    BleAdStructure, BleAddressType, BleLeDeviceAddress, BleLeRole, BleOobRecord, BLE_OOB_MIME_TYPE,
};
pub use connection_handover::{HandoverRequest, HandoverSelect, CONNECTION_HANDOVER_SERVICE_NAME};
