use std::fmt;

use hmac::{Hmac, Mac};
use mdoc_core::{
    derive_emac_key, derive_shared_secret, CoseAlg, CoseKeyPrivate, CoseMac0, ElementValue,
    MacStructure, MdocDocument, SessionTranscript, TaggedCborBytes, MAC0_CONTEXT,
};
use minicbor::bytes::ByteVec;
use sha2::Sha256;

use crate::mdoc_device_auth::{
    build_device_authentication_bytes, verify_key_authorizations, MdocDeviceAuthError,
};
use crate::VerifiedMso;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct MdocMacAuthContext {
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
    pub verified_mso: VerifiedMso,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdocMacAuthError {
    DeviceAuthModeInvalid,
    DeviceAuthenticationEncodingFailed(String),
    DeviceAuthPayloadMismatch,
    DeviceMacInvalid(String),
    UnauthorizedDeviceNamespace {
        namespace: String,
    },
    UnauthorizedDeviceSignedElement {
        namespace: String,
        element_identifier: String,
    },
}

impl fmt::Display for MdocMacAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceAuthModeInvalid => {
                write!(f, "deviceAuth must contain exactly one of deviceSignature or deviceMac")
            }
            Self::DeviceAuthenticationEncodingFailed(message) => {
                write!(f, "failed to encode DeviceAuthentication: {message}")
            }
            Self::DeviceAuthPayloadMismatch => {
                write!(f, "deviceMac payload does not match DeviceAuthentication bytes")
            }
            Self::DeviceMacInvalid(message) => write!(f, "invalid deviceMac: {message}"),
            Self::UnauthorizedDeviceNamespace { namespace } => {
                write!(f, "unauthorized DeviceSigned namespace: {namespace}")
            }
            Self::UnauthorizedDeviceSignedElement {
                namespace,
                element_identifier,
            } => write!(
                f,
                "unauthorized DeviceSigned element: namespace={namespace}, elementIdentifier={element_identifier}"
            ),
        }
    }
}

impl std::error::Error for MdocMacAuthError {}

pub fn verify_mdoc_mac_auth(
    doc: &MdocDocument,
    e_reader_key_private: &CoseKeyPrivate,
    ctx: &MdocMacAuthContext,
) -> Result<(), MdocMacAuthError> {
    let device_auth = &doc.device_signed.device_auth;
    let Some(device_mac) = device_auth.device_mac.as_ref() else {
        return Err(MdocMacAuthError::DeviceAuthModeInvalid);
    };
    if device_auth.device_signature.is_some() {
        return Err(MdocMacAuthError::DeviceAuthModeInvalid);
    }

    let expected_payload = build_device_authentication_bytes(
        &ctx.session_transcript,
        &doc.doc_type,
        &doc.device_signed.name_spaces,
    )
    .map_err(map_device_auth_error)?;
    let shared_secret = derive_shared_secret(
        e_reader_key_private,
        &ctx.verified_mso.mso.device_key_info.device_key,
    )
    .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))?;

    let emac_key = derive_emac_key(&shared_secret, &ctx.session_transcript)
        .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))?;

    verify_device_mac(device_mac, &emac_key, &expected_payload)?;
    verify_key_authorizations(doc, &ctx.verified_mso).map_err(map_device_auth_error)
}

fn verify_device_mac(
    device_mac: &ElementValue,
    emac_key: &[u8; 32],
    expected_payload: &[u8],
) -> Result<(), MdocMacAuthError> {
    let mac0: CoseMac0 = device_mac
        .decode()
        .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))?;
    let protected = mac0
        .protected
        .decode()
        .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))?;

    match protected.alg {
        Some(CoseAlg::HMAC256256) => {}
        Some(alg) => {
            return Err(MdocMacAuthError::DeviceMacInvalid(format!(
                "unsupported COSE_Mac0 algorithm: {alg:?}"
            )))
        }
        None => {
            return Err(MdocMacAuthError::DeviceMacInvalid(
                "COSE_Mac0 algorithm is missing from protected header".to_string(),
            ))
        }
    }

    if let Some(payload) = mac0.payload.as_ref() {
        if payload.raw_cbor_bytes() != expected_payload {
            return Err(MdocMacAuthError::DeviceAuthPayloadMismatch);
        }
    }

    let mac_structure = build_mac_structure_bytes(&mac0, expected_payload, &[])?;
    let mut hmac = HmacSha256::new_from_slice(emac_key)
        .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))?;
    hmac.update(&mac_structure);
    if hmac.verify_slice(mac0.tag.as_slice()).is_ok() {
        return Ok(());
    }

    Err(MdocMacAuthError::DeviceMacInvalid(
        "COSE_Mac0 tag verification failed".to_string(),
    ))
}

fn build_mac_structure_bytes(
    mac0: &CoseMac0,
    payload: &[u8],
    external_aad: &[u8],
) -> Result<Vec<u8>, MdocMacAuthError> {
    minicbor::to_vec(MacStructure {
        context: MAC0_CONTEXT.to_string(),
        body_protected: ByteVec::from(mac0.protected.raw_cbor_bytes().to_vec()),
        external_aad: ByteVec::from(external_aad.to_vec()),
        payload: ByteVec::from(payload.to_vec()),
    })
    .map_err(|err| MdocMacAuthError::DeviceMacInvalid(err.to_string()))
}

fn map_device_auth_error(err: MdocDeviceAuthError) -> MdocMacAuthError {
    match err {
        MdocDeviceAuthError::DeviceAuthModeInvalid => MdocMacAuthError::DeviceAuthModeInvalid,
        MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(message) => {
            MdocMacAuthError::DeviceAuthenticationEncodingFailed(message)
        }
        MdocDeviceAuthError::DeviceAuthPayloadMismatch => {
            MdocMacAuthError::DeviceAuthPayloadMismatch
        }
        MdocDeviceAuthError::UnauthorizedDeviceNamespace { namespace } => {
            MdocMacAuthError::UnauthorizedDeviceNamespace { namespace }
        }
        MdocDeviceAuthError::UnauthorizedDeviceSignedElement {
            namespace,
            element_identifier,
        } => MdocMacAuthError::UnauthorizedDeviceSignedElement {
            namespace,
            element_identifier,
        },
        MdocDeviceAuthError::DeviceSignatureInvalid(message) => {
            MdocMacAuthError::DeviceMacInvalid(message)
        }
    }
}
