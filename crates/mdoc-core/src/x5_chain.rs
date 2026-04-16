use std::ops::Deref;

use anyhow::Result;
use minicbor::{Decode, Decoder, Encode, Encoder};
use x509_cert::der::{Decode as DerDecode, Encode as DerEncode};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct X5Chain(Vec<x509_cert::Certificate>);

impl X5Chain {
    pub fn from_certificates(certs: Vec<x509_cert::Certificate>) -> Result<Self> {
        if certs.is_empty() {
            anyhow::bail!("x5chain must contain at least one certificate");
        }
        Ok(Self(certs))
    }

    pub fn as_slice(&self) -> &[x509_cert::Certificate] {
        &self.0
    }
}

impl AsRef<[x509_cert::Certificate]> for X5Chain {
    fn as_ref(&self) -> &[x509_cert::Certificate] {
        self.as_slice()
    }
}

impl Deref for X5Chain {
    type Target = [x509_cert::Certificate];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<C> Encode<C> for X5Chain {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self.0.len() {
            0 => {
                return Err(minicbor::encode::Error::message(
                    "x5chain must contain at least one certificate",
                ));
            }
            1 => {
                let der = self.0[0].to_der().map_err(|_| {
                    minicbor::encode::Error::message("failed to encode x5chain certificate to DER")
                })?;
                e.bytes(&der)?;
            }
            _ => {
                e.array(self.0.len() as u64)?;
                for cert in &self.0 {
                    let der = cert.to_der().map_err(|_| {
                        minicbor::encode::Error::message(
                            "failed to encode x5chain certificate to DER",
                        )
                    })?;
                    e.bytes(&der)?;
                }
            }
        };

        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for X5Chain {
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Bytes => {
                let der = d.bytes()?;
                let cert = x509_cert::Certificate::from_der(der).map_err(|_| {
                    minicbor::decode::Error::message("x5chain certificate is not valid DER X.509")
                })?;
                Ok(Self(vec![cert]))
            }
            minicbor::data::Type::Array => {
                let len = d.array()?.ok_or_else(|| {
                    minicbor::decode::Error::message("x5chain array must be definite-length")
                })?;
                if len == 0 {
                    return Err(minicbor::decode::Error::message(
                        "x5chain array must contain at least one certificate",
                    ));
                }
                let mut certs = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    let der = d.bytes()?;
                    let cert = x509_cert::Certificate::from_der(der).map_err(|_| {
                        minicbor::decode::Error::message(
                            "x5chain certificate is not valid DER X.509",
                        )
                    })?;
                    certs.push(cert);
                }
                Ok(Self(certs))
            }
            _ => Err(minicbor::decode::Error::message(
                "x5chain must be a bstr certificate or array of bstr certificates",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMap;
    use minicbor::Encoder;

    #[test]
    fn x5chain_rejects_non_x509_der() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<X5Chain>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn x5chain_rejects_empty_array_form() {
        let mut e = Encoder::new(Vec::new());
        e.map(1).unwrap();
        e.i8(33).unwrap();
        e.array(0).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<HeaderMap>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn x5chain_rejects_invalid_der_in_array_form() {
        let mut e = Encoder::new(Vec::new());
        e.map(1).unwrap();
        e.i8(33).unwrap();
        e.array(1).unwrap();
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<HeaderMap>(&encoded);
        assert!(result.is_err());
    }
}
