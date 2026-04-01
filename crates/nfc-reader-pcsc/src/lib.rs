use anyhow::Context as _;
use nfc_reader::{NfcReader, NfcTag};
use std::time::{Duration, Instant};

const MAX_APDU_RESPONSE_SIZE: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const POST_CONNECT_SETTLE_DELAY: Duration = Duration::from_millis(700);

#[derive(Debug, Clone)]
pub struct PcscReaderConfig {
    pub scope: pcsc::Scope,
    pub poll_interval: Duration,
    pub post_connect_settle_delay: Duration,
    /// 使用するリーダー名を指定する。None の場合は最初に見つかったリーダーを使用する。
    pub reader_name: Option<String>,
}

impl Default for PcscReaderConfig {
    fn default() -> Self {
        Self {
            scope: pcsc::Scope::User,
            poll_interval: POLL_INTERVAL,
            post_connect_settle_delay: POST_CONNECT_SETTLE_DELAY,
            reader_name: None,
        }
    }
}

#[derive(Debug)]
pub struct PcscReader {
    config: PcscReaderConfig,
}

impl PcscReader {
    pub fn new() -> Self {
        Self::with_config(PcscReaderConfig::default())
    }

    pub fn with_config(config: PcscReaderConfig) -> Self {
        Self { config }
    }

    pub fn with_reader_name(reader_name: impl Into<String>) -> Self {
        Self::with_config(PcscReaderConfig {
            reader_name: Some(reader_name.into()),
            ..Default::default()
        })
    }

    /// 利用可能なカードリーダー名の一覧を返す。
    pub fn list_readers() -> anyhow::Result<Vec<String>> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).context("PC/SC establish failed")?;
        let mut buf = [0u8; 4096];
        let names = ctx
            .list_readers(&mut buf)
            .context("PC/SC list_readers failed")?
            .map(|r| r.to_string_lossy().into_owned())
            .collect();
        Ok(names)
    }
}

impl Default for PcscReader {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PcscTag {
    _ctx: pcsc::Context,
    card: pcsc::Card,
}

impl PcscTag {
    fn new(ctx: pcsc::Context, card: pcsc::Card) -> Self {
        Self { _ctx: ctx, card }
    }
}

#[allow(async_fn_in_trait)]
impl NfcTag for PcscTag {
    async fn transceive(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut recv_buf = vec![0u8; MAX_APDU_RESPONSE_SIZE];
        let response = self
            .card
            .transmit(data, &mut recv_buf)
            .context("PC/SC transmit failed")?;
        Ok(response.to_vec())
    }
}

#[allow(async_fn_in_trait)]
impl NfcReader for PcscReader {
    type NfcTag<'a> = PcscTag;

    async fn connect(&mut self, timeout: Duration) -> anyhow::Result<Option<Self::NfcTag<'_>>> {
        let ctx = pcsc::Context::establish(self.config.scope).context("PC/SC establish failed")?;
        let buffer_len = ctx
            .list_readers_len()
            .context("PC/SC list_readers failed")?;
        let readers_buf = &mut vec![0u8; buffer_len];
        let reader = ctx
            .list_readers(readers_buf)
            .context("PC/SC list_readers failed")?
            .filter(|reader| {
                if let Some(ref name) = self.config.reader_name {
                    reader.to_string_lossy() == name.as_str()
                } else {
                    true
                }
            })
            .next()
            .ok_or_else(|| anyhow::anyhow!("No PC/SC readers found"))?;

        let start = Instant::now();
        loop {
            match ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
                Ok(card) => {
                    std::thread::sleep(self.config.post_connect_settle_delay);
                    return Ok(Some(PcscTag::new(ctx, card)));
                }
                Err(pcsc::Error::NoSmartcard) | Err(pcsc::Error::RemovedCard) => {
                    std::thread::sleep(self.config.poll_interval);
                }
                Err(err) => {
                    return Err(anyhow::Error::new(err).context("PC/SC connect failed"));
                }
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
        }
    }
}
