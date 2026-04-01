#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngagementMethod {
    Nfc,
    QrCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Ble,
    Wifi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderFlowEvent {
    WaitingForEngagement(EngagementMethod),
    EngagementConnected(EngagementMethod),
    TransportConnected(TransportKind),
    WaitingForUserApproval,
    DeviceResponseReceived,
}

pub trait ReaderFlowObserver {
    fn on_event(&self, event: ReaderFlowEvent);
}
