#[allow(async_fn_in_trait)]
pub trait NfcReader {
    type NfcTag<'a>: NfcTag
    where
        Self: 'a;

    async fn connect(
        &mut self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Option<Self::NfcTag<'_>>>;
}

#[allow(async_fn_in_trait)]
pub trait NfcTag {
    async fn transceive(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct DummyTag;

#[derive(Debug, Default)]
pub struct DummyDetector;

impl NfcTag for DummyTag {
    async fn transceive(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

impl NfcReader for DummyDetector {
    type NfcTag<'a> = DummyTag;

    async fn connect(
        &mut self,
        _timeout: std::time::Duration,
    ) -> anyhow::Result<Option<Self::NfcTag<'_>>> {
        Ok(Some(DummyTag))
    }
}
