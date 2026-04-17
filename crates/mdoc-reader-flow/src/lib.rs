use anyhow::{anyhow, Context};
use log::info;
use mdoc_core::{CoseKeyPrivate, DeviceRequest, DeviceResponse, SessionTranscript};
use mdoc_data_retrieval_flow::DataRetrievalFlowObserver;
use mdoc_security::IssuerDataAuthContext;
use mdoc_transport::{BleTransportParams, MdocTransportConnector};
use nfc_reader::NfcReader;
use std::time::SystemTime;
use uuid::Uuid;

pub async fn read_mdoc<T, F>(
    nfc: &mut T,
    transport: &F,
    service_uuid: Option<Uuid>,
    e_reader_key_private: &CoseKeyPrivate,
    device_request: &DeviceRequest,
    observer: Option<&dyn DataRetrievalFlowObserver>,
    iaca_cert: Option<&x509_cert::Certificate>,
    skip_crl: bool,
) -> anyhow::Result<DeviceResponse>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = BleTransportParams> + ?Sized,
{
    let result = mdoc_data_retrieval_flow_nfc_ble::read_mdoc(
        nfc,
        transport,
        device_request,
        e_reader_key_private,
        service_uuid,
        observer,
    )
    .await?;

    validate_device_response(
        &result.device_response,
        e_reader_key_private,
        &result.session_transcript,
        iaca_cert,
        skip_crl,
    )
    .await?;

    Ok(result.device_response)
}

async fn validate_device_response(
    response: &DeviceResponse,
    e_self_private_key: &CoseKeyPrivate,
    session_transcript: &SessionTranscript,
    iaca_cert: Option<&x509_cert::Certificate>,
    skip_crl: bool,
) -> anyhow::Result<()> {
    if let Some(response_documents) = response.documents.as_ref() {
        for doc in response_documents {
            if let Some(cert) = iaca_cert {
                let result = mdoc_security::validate_document_x5chain(
                    &doc.issuer_signed.issuer_auth,
                    cert,
                    skip_crl,
                    SystemTime::now(),
                )
                .await
                .with_context(|| format!("certificate_validation failed docType={}", doc.doc_type))?;
                info!(
                    "[OK] Certificate validation result for docType={}: {:?}",
                    doc.doc_type, result
                );
            }

            let verified = mdoc_security::verify_issuer_data_auth(
                doc,
                &IssuerDataAuthContext {
                    now: chrono::Utc::now(),
                    expected_doc_type: Some(doc.doc_type.clone()),
                },
            )
            .map_err(|err| {
                anyhow!(
                    "issuer_data_auth verification failed docType={} error={err}",
                    doc.doc_type
                )
            })?;

            mdoc_security::verify_mdoc_device_auth(
                &doc.device_signed,
                &verified.mso.device_key_info,
                e_self_private_key,
                session_transcript,
                &doc.doc_type,
            )
            .map_err(|err| {
                anyhow!(
                    "mdoc_device_auth verification failed docType={} error=failed to decode session transcript: {err}",
                    doc.doc_type
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_device_response;
    use mdoc_core::{
        CoseKeyPrivate, CoseSign1, DeviceAuth, DeviceResponse, DeviceSigned, HeaderMap,
        IssuerSigned, MdocDocument, ProtectedHeaderMap, SessionTranscript, TaggedCborBytes,
    };
    use minicbor::Encoder;
    use minicbor::bytes::ByteVec;
    use std::collections::BTreeMap;

    fn empty_response() -> DeviceResponse {
        DeviceResponse {
            version: "1.0".to_string(),
            status: 0,
            documents: None,
            document_errors: None,
        }
    }

    fn invalid_document_response(doc_type: &str) -> DeviceResponse {
        DeviceResponse {
            version: "1.0".to_string(),
            status: 0,
            documents: Some(vec![MdocDocument {
                doc_type: doc_type.to_string(),
                issuer_signed: IssuerSigned {
                    issuer_auth: CoseSign1::new(
                        ProtectedHeaderMap::from(&HeaderMap::default()),
                        HeaderMap::default(),
                        None,
                        ByteVec::from(vec![]),
                    ),
                    name_spaces: None,
                },
                device_signed: DeviceSigned {
                    name_spaces: TaggedCborBytes::from(&BTreeMap::new()),
                    device_auth: DeviceAuth {
                        device_signature: None,
                        device_mac: None,
                    },
                },
                errors: None,
            }]),
            document_errors: None,
        }
    }

    fn dummy_session_transcript() -> SessionTranscript {
        let reader_key = CoseKeyPrivate::new().unwrap().to_public();
        let tagged_key = TaggedCborBytes::from(&reader_key);
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(3).unwrap();
        encoder.null().unwrap();
        encoder.encode(tagged_key).unwrap();
        encoder.array(2).unwrap();
        encoder.bytes(&[]).unwrap();
        encoder.null().unwrap();
        minicbor::decode(&encoder.into_writer()).unwrap()
    }

    #[tokio::test]
    async fn validate_device_response_accepts_missing_documents() {
        let response = empty_response();

        validate_device_response(
            &response,
            &CoseKeyPrivate::new().unwrap(),
            &dummy_session_transcript(),
            None,
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn validate_device_response_accepts_empty_document_list() {
        let response = DeviceResponse {
            documents: Some(vec![]),
            ..empty_response()
        };

        validate_device_response(
            &response,
            &CoseKeyPrivate::new().unwrap(),
            &dummy_session_transcript(),
            None,
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn validate_device_response_returns_contextualized_error_without_iaca_cert() {
        let response = invalid_document_response("org.iso.18013.5.1.mDL");
        let err = validate_device_response(
            &response,
            &CoseKeyPrivate::new().unwrap(),
            &dummy_session_transcript(),
            None,
            false,
        )
        .await
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("issuer_data_auth verification failed"));
        assert!(message.contains("docType=org.iso.18013.5.1.mDL"));
    }
}
