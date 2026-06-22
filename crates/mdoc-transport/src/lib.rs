use anyhow::Result;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct BleTransportParams {
    pub service_uuid: Uuid,
    pub ident: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiAwareTransportParams {
    pub service_name: String,
    pub pass_phrase: Option<String>,
    pub operating_class: Option<u64>,
    pub channel_number: Option<u64>,
    pub supported_bands: Option<Vec<u8>>,
}

#[allow(async_fn_in_trait)]
pub trait MdocTransport {
    async fn send(&mut self, message: &[u8]) -> Result<()>;
    async fn receive_packets(&mut self) -> Result<Vec<Vec<u8>>>;

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let packets = self.receive_packets().await?;
        let total_len: usize = packets.iter().map(Vec::len).sum();
        let mut joined = Vec::with_capacity(total_len);
        for packet in packets {
            joined.extend_from_slice(&packet);
        }
        Ok(joined)
    }
}

#[allow(async_fn_in_trait)]
pub trait MdocTransportConnector {
    type Transport: MdocTransport;
    type Params;

    async fn connect(&self, params: Self::Params) -> Result<Self::Transport>;
}
