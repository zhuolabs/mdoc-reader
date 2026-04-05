use minicbor::bytes::ByteVec;
use minicbor::data::{Tag, Tagged};
use minicbor::decode::{Decode, Decoder, Error as DecodeError};
use minicbor::encode::{Encode, Encoder, Error as EncodeError, Write};
use std::fmt;
use std::marker::PhantomData;

#[derive(Clone, PartialEq, Eq)]
pub struct TaggedCborBytes<T> {
    raw_cbor_bytes: ByteVec,
    marker: PhantomData<fn() -> T>,
}

impl<T> TaggedCborBytes<T> {
    pub fn from_raw_bytes(raw_cbor_bytes: impl Into<ByteVec>) -> Self {
        Self {
            raw_cbor_bytes: raw_cbor_bytes.into(),
            marker: PhantomData,
        }
    }

    pub fn raw_cbor_bytes(&self) -> &[u8] {
        &self.raw_cbor_bytes
    }

    pub fn decode(&self) -> Result<T, DecodeError>
    where
        T: for<'a> Decode<'a, ()>,
    {
        minicbor::decode(&self.raw_cbor_bytes)
            .map_err(|_| DecodeError::message("failed to decode tag24 inner value"))
    }
}

impl<T> fmt::Debug for TaggedCborBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedCborBytes")
            .field("raw_cbor_bytes", &self.raw_cbor_bytes)
            .finish()
    }
}

impl<T> From<&T> for TaggedCborBytes<T>
where
    T: Encode<()>,
{
    fn from(value: &T) -> Self {
        Self::from_raw_bytes(
            minicbor::to_vec(value).expect("encoding TaggedCborBytes inner value should not fail"),
        )
    }
}

impl<T, C> Encode<C> for TaggedCborBytes<T>
where
    T: Encode<()>,
{
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.tag(Tag::new(24))?;
        e.bytes(&self.raw_cbor_bytes)?;
        Ok(())
    }
}

impl<'b, T, C> Decode<'b, C> for TaggedCborBytes<T>
where
    T: for<'a> Decode<'a, ()>,
{
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let tagged: Tagged<24, ByteVec> = d.decode()?;
        Ok(Self::from_raw_bytes(tagged.into_value()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct {
        #[n(0)]
        pub version: String,
    }

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct2 {
        #[n(0)]
        pub tagged: TaggedCborBytes<TestStruct>,
    }

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct3 {
        #[n(0)]
        pub tagged: Tagged<24, ByteVec>,
    }

    #[test]
    fn tagged_cbor_bytes_is_tagged24() -> anyhow::Result<()> {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let value: Tagged<24, ByteVec> = Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?));
        let value2: TaggedCborBytes<TestStruct> = TaggedCborBytes::from(&raw);

        let encoded = minicbor::to_vec(&value).expect("failed to encode");
        let encoded_value2 = minicbor::to_vec(&value2).expect("failed to encode value2");

        assert_eq!(encoded, encoded_value2);

        Ok(())
    }

    #[test]
    fn test_tag24_cbor() -> anyhow::Result<()> {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let value2 = TestStruct2 {
            tagged: TaggedCborBytes::from(&raw),
        };
        let value3 = TestStruct3 {
            tagged: Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?)),
        };
        let encoded_value2 = minicbor::to_vec(&value2).expect("failed to encode value2");
        let encoded_value3 = minicbor::to_vec(&value3).expect("failed to encode value3");

        assert_eq!(encoded_value2, encoded_value3);
        Ok(())
    }

    #[test]
    fn tagged_cbor_bytes_decodes_on_demand() {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let tagged = TaggedCborBytes::from(&raw);

        assert_eq!(tagged.decode().unwrap().version, raw.version);
    }
}
