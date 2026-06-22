use anyhow::{Context, Result};
use async_trait::async_trait;
use connection_handover::{
    CONNECTION_HANDOVER_SERVICE_NAME, HandoverRequest, HandoverSelect, WifiAwareRecord,
};
use mdoc_core::{
    CoseKeyPrivate, CoseKeyPublic, DeviceEngagement, DeviceRequest, DeviceResponse, NFCHandover,
    ReaderEngagement, SessionData, SessionEstablishment, SessionTranscript, TaggedCborBytes,
    wifi_aware_service_name,
};
use mdoc_data_retrieval_flow::{
    DataRetrievalFlow, DataRetrievalFlowEvent, DataRetrievalFlowObserver, DataRetrievalResult,
    EngagementMethod, TransportKind,
};
use mdoc_security::{MdocRole, SessionEncryption};
use mdoc_transport::{MdocTransport, MdocTransportConnector, WifiAwareTransportParams};
use nfc_reader::NfcReader;
use packet_reorder_workaround::try_decode_and_decrypt_session_data;
use std::convert::TryFrom;
use tnep::TnepClient;

mod packet_reorder_workaround;

const SESSION_DATA_STATUS_SESSION_TERMINATION: u64 = 20;

pub struct NfcWifiAwareDataRetrievalFlow<'a, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = WifiAwareTransportParams> + ?Sized,
{
    reader: &'a mut T,
    transport_factory: &'a F,
}

impl<'a, T, F> NfcWifiAwareDataRetrievalFlow<'a, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = WifiAwareTransportParams> + ?Sized,
{
    pub fn new(reader: &'a mut T, transport_factory: &'a F) -> Self {
        Self {
            reader,
            transport_factory,
        }
    }
}

#[async_trait(?Send)]
impl<T, F> DataRetrievalFlow for NfcWifiAwareDataRetrievalFlow<'_, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = WifiAwareTransportParams> + ?Sized,
{
    type Error = anyhow::Error;

    async fn retrieve_data(
        &mut self,
        device_request: &DeviceRequest,
        e_reader_key_private: &CoseKeyPrivate,
        observer: Option<&dyn DataRetrievalFlowObserver>,
    ) -> Result<DataRetrievalResult> {
        notify_event(
            observer,
            DataRetrievalFlowEvent::WaitingForEngagement(EngagementMethod::Nfc),
        );

        let mut nfc = self
            .reader
            .connect(std::time::Duration::from_secs(120))
            .await?
            .ok_or_else(|| anyhow::anyhow!("NFC card was not detected within timeout"))?;

        notify_event(
            observer,
            DataRetrievalFlowEvent::EngagementConnected(EngagementMethod::Nfc),
        );

        let mut tnep = TnepClient::new(&mut nfc)
            .await
            .context("failed to initialize TNEP client")?;
        let mut handover_service = tnep
            .select(CONNECTION_HANDOVER_SERVICE_NAME)
            .await
            .context("failed to select TNEP handover service")?;

        let reader_engagement_record = &ReaderEngagement::default();
        let wifi_aware_record = &WifiAwareRecord::default();
        let handover_request =
            HandoverRequest::new(wifi_aware_record, vec![reader_engagement_record])?;

        let handover_request_message = (&handover_request).into();
        let handover_select_message = handover_service
            .exchange(&handover_request_message)
            .await
            .context("TNEP handover exchange failed")?;

        let handover_select: HandoverSelect = (&handover_select_message)
            .try_into()
            .map_err(|_| anyhow::anyhow!("Handover Select message parse failed"))?;

        let (wifi_aware, device_engagement) = handover_select
            .find_carrier_auxiliary(
                |record| WifiAwareRecord::try_from(record).ok(),
                |record| DeviceEngagement::try_from(record).ok(),
            )
            .ok_or_else(|| anyhow::anyhow!("Wi-Fi Aware carrier with DeviceEngagement auxiliary record not found in Handover Select"))?;

        let e_device_key_bytes = device_engagement.e_device_key_bytes();
        let service_name = match wifi_aware.service_name.clone() {
            Some(service_name) => service_name,
            None => wifi_aware_service_name(e_device_key_bytes)?,
        };
        let e_reader_key = e_reader_key_private.to_public();
        let session_transcript = SessionTranscript(
            Some(TaggedCborBytes::from(&device_engagement)),
            TaggedCborBytes::from(&e_reader_key),
            NFCHandover(
                (&handover_select_message).try_into()?,
                Some((&handover_request_message).try_into()?),
            ),
        );

        let mut transport = self
            .transport_factory
            .connect(WifiAwareTransportParams {
                service_name,
                pass_phrase: wifi_aware.pass_phrase.clone(),
                operating_class: wifi_aware
                    .channel_info
                    .as_ref()
                    .map(|v| v.operating_class as u64),
                channel_number: wifi_aware
                    .channel_info
                    .as_ref()
                    .map(|v| v.channel_number as u64),
                supported_bands: None,
            })
            .await?;

        notify_event(
            observer,
            DataRetrievalFlowEvent::TransportConnected(TransportKind::Wifi),
        );

        let device_response = do_reader_flow_with_transport(
            &mut transport,
            &e_device_key_bytes.decode()?,
            &session_transcript,
            e_reader_key_private,
            device_request,
            observer,
        )
        .await?;

        Ok(DataRetrievalResult {
            device_response,
            session_transcript,
        })
    }
}

async fn do_reader_flow_with_transport<T>(
    transport: &mut T,
    e_device_key: &CoseKeyPublic,
    session_transcript: &SessionTranscript,
    e_reader_key_private: &CoseKeyPrivate,
    device_request: &DeviceRequest,
    observer: Option<&dyn DataRetrievalFlowObserver>,
) -> Result<DeviceResponse>
where
    T: MdocTransport + ?Sized,
{
    let e_reader_key_public = e_reader_key_private.to_public();
    let encoded_device_request = minicbor::to_vec(device_request)?;
    let session_transcript_bytes = TaggedCborBytes::from(session_transcript);

    let session_encryption = SessionEncryption::new(
        MdocRole::Reader,
        e_reader_key_private,
        e_device_key,
        &session_transcript_bytes,
    )?;
    let encrypted_request = session_encryption.encrypt_data(&encoded_device_request, 1)?;
    let session_establishment = SessionEstablishment {
        e_reader_key: TaggedCborBytes::from(&e_reader_key_public),
        data: encrypted_request.into(),
    };
    let encoded_session_establishment = minicbor::to_vec(session_establishment)?;
    transport.send(&encoded_session_establishment).await?;
    notify_event(observer, DataRetrievalFlowEvent::WaitingForUserApproval);

    let session_data_packets = transport.receive_packets().await?;
    let decoded = try_decode_and_decrypt_session_data(&session_data_packets, |joined| {
        decode_and_decrypt_session_data(joined, &session_encryption, 1)
    })?;
    if decoded.message.is_empty() {
        anyhow::bail!("device did not return SessionData");
    }

    let device_response = minicbor::decode(&decoded.message)?;
    notify_event(observer, DataRetrievalFlowEvent::DeviceResponseReceived);

    if decoded.parsed.status != Some(SESSION_DATA_STATUS_SESSION_TERMINATION) {
        let termination = minicbor::to_vec(SessionData {
            data: None,
            status: Some(SESSION_DATA_STATUS_SESSION_TERMINATION),
        })?;
        transport.send(&termination).await?;
    }

    Ok(device_response)
}

fn notify_event(observer: Option<&dyn DataRetrievalFlowObserver>, event: DataRetrievalFlowEvent) {
    if let Some(observer) = observer {
        observer.on_event(event);
    }
}

fn head_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02X}", b))
        .collect()
}

struct DecodedSessionData {
    parsed: SessionData,
    message: Vec<u8>,
}

fn decode_and_decrypt_session_data(
    session_data: &[u8],
    session_encryption: &SessionEncryption,
    decrypt_counter: u32,
) -> Result<DecodedSessionData> {
    let parsed: SessionData = minicbor::decode(session_data).with_context(|| {
        format!(
            "failed to decode session data: len={} head={}",
            session_data.len(),
            head_hex(session_data)
        )
    })?;
    let ciphertext = parsed
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("session data does not include encrypted data"))?;
    let message = session_encryption
        .decrypt_data(ciphertext.as_slice(), decrypt_counter)
        .with_context(|| {
            format!(
                "failed to decrypt session message: len={} head={}",
                session_data.len(),
                head_hex(session_data)
            )
        })?;
    Ok(DecodedSessionData { parsed, message })
}
