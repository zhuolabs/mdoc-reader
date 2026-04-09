use std::time::SystemTime;

use log::{info, warn};
use reqwest::blocking::Client;
use url::Url;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::num_bigint::BigUint;
use x509_parser::parse_x509_crl;
use x509_parser::prelude::FromDer;

use crate::ValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidationOutcome {
    Valid { crl_checked: bool },
}

pub fn download_iacacert_der(iacacert_url: Url) -> Result<Vec<u8>, ValidationError> {
    if iacacert_url.scheme() != "https" {
        return Err(ValidationError::Unsupported(
            "only https iacacert URLs are allowed".to_string(),
        ));
    }

    info!("certificate_validation: downloading IACA certificate url={iacacert_url}");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let response = client
        .get(iacacert_url.clone())
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let bytes = response
        .bytes()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    info!(
        "certificate_validation: downloaded IACA certificate url={} bytes={}",
        iacacert_url,
        bytes.len()
    );

    Ok(bytes.to_vec())
}

pub fn validate_reader_auth_certificate(
    iacacert_der: &[u8],
    x5chain: &[Vec<u8>],
    now: SystemTime,
) -> Result<CertificateValidationOutcome, ValidationError> {
    if x5chain.is_empty() {
        return Err(ValidationError::InvalidChain);
    }

    info!(
        "certificate_validation: start iaca_bytes={} chain_len={}",
        iacacert_der.len(),
        x5chain.len()
    );

    let (_, iaca) = x509_parser::certificate::X509Certificate::from_der(iacacert_der)
        .map_err(|e| ValidationError::CertificateParse(e.to_string()))?;

    let mut certs = Vec::with_capacity(x5chain.len());
    for der in x5chain {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| ValidationError::CertificateParse(e.to_string()))?;
        certs.push(cert);
    }

    validate_time(&iaca, now)?;
    for cert in &certs {
        validate_time(cert, now)?;
    }

    validate_basic_constraints(&iaca, &certs)?;
    validate_key_usage(&certs[0])?;

    for pair in certs.windows(2) {
        let child = &pair[0];
        let issuer = &pair[1];
        if child.issuer() != issuer.subject() {
            return Err(ValidationError::InvalidChain);
        }
    }

    let last = certs.last().ok_or(ValidationError::InvalidChain)?;
    if last.issuer() != iaca.subject() {
        return Err(ValidationError::InvalidChain);
    }

    let mut crl_checked = false;
    if let Some(crl_url) = extract_first_crl_uri(&iaca) {
        info!("certificate_validation: CRL distribution point found url={crl_url}");
        let crl_der = download_crl_der(&crl_url)?;
        let (_, crl) =
            parse_x509_crl(&crl_der).map_err(|e| ValidationError::CrlParse(e.to_string()))?;
        crl_checked = true;
        info!(
            "certificate_validation: CRL parsed url={} bytes={} revoked_entries={}",
            crl_url,
            crl_der.len(),
            crl.iter_revoked_certificates().count()
        );

        let leaf_serial = BigUint::from_bytes_be(certs[0].raw_serial());
        for revoked in crl.iter_revoked_certificates() {
            let serial = BigUint::from_bytes_be(revoked.raw_serial());
            if serial == leaf_serial {
                warn!("certificate_validation: leaf certificate serial matched CRL entry");
                return Err(ValidationError::Revoked);
            }
        }
    } else {
        info!("certificate_validation: no CRL distribution point found in IACA certificate");
    }

    info!("certificate_validation: completed crl_checked={crl_checked}");
    Ok(CertificateValidationOutcome::Valid { crl_checked })
}

fn validate_time(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    now: SystemTime,
) -> Result<(), ValidationError> {
    let now = time::OffsetDateTime::from(now);
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    if now < not_before || now > not_after {
        return Err(ValidationError::Expired);
    }
    Ok(())
}

fn validate_basic_constraints(
    iaca: &x509_parser::certificate::X509Certificate<'_>,
    chain: &[x509_parser::certificate::X509Certificate<'_>],
) -> Result<(), ValidationError> {
    if let Ok(Some(bc)) = iaca.basic_constraints() {
        if !bc.value.ca {
            return Err(ValidationError::InvalidChain);
        }
    }

    if let Some(leaf) = chain.first() {
        if let Ok(Some(bc)) = leaf.basic_constraints() {
            if bc.value.ca {
                return Err(ValidationError::InvalidChain);
            }
        }
    }

    for cert in chain.iter().skip(1) {
        if let Ok(Some(bc)) = cert.basic_constraints() {
            if !bc.value.ca {
                return Err(ValidationError::InvalidChain);
            }
        }
    }

    Ok(())
}

fn validate_key_usage(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), ValidationError> {
    if let Ok(Some(ku)) = leaf.key_usage() {
        if !ku.value.digital_signature() {
            return Err(ValidationError::InvalidChain);
        }
    }
    Ok(())
}

fn extract_first_crl_uri(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<Url> {
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in &points.points {
                if let Some(name) = &point.distribution_point {
                    if let x509_parser::extensions::DistributionPointName::FullName(names) = name {
                        for general_name in names {
                            if let GeneralName::URI(uri) = general_name {
                                if let Ok(url) = Url::parse(uri) {
                                    return Some(url);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn download_crl_der(crl_url: &Url) -> Result<Vec<u8>, ValidationError> {
    if crl_url.scheme() != "https" {
        return Err(ValidationError::Unsupported(
            "only https crl URLs are supported".to_string(),
        ));
    }

    info!("certificate_validation: downloading CRL url={crl_url}");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let response = client
        .get(crl_url.clone())
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|err| {
            warn!("certificate_validation: CRL download failed url={} error={err}", crl_url);
            ValidationError::CrlUnavailable
        })?;

    let bytes = response
        .bytes()
        .map_err(|err| {
            warn!(
                "certificate_validation: CRL response body read failed url={} error={err}",
                crl_url
            );
            ValidationError::CrlUnavailable
        })?;

    info!(
        "certificate_validation: downloaded CRL url={} bytes={}",
        crl_url,
        bytes.len()
    );

    Ok(bytes.to_vec())
}
