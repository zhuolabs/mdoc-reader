macro_rules! cbor_string_map_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            required {
                $( $rvis:vis $rfield:ident : $rty:ty => $rkey:literal, )*
            }
            optional {
                $( $ovis:vis $ofield:ident : $oty:ty => $okey:literal, )*
            }
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $rvis $rfield: $rty, )*
            $( $ovis $ofield: Option<$oty>, )*
        }

        impl<C> minicbor::encode::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                e: &mut minicbor::encode::Encoder<W>,
                _ctx: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                let required_entries: u64 = 0 $(+ { let _ = $rkey; 1u64 })*;
                let optional_entries: u64 = 0 $(+ if self.$ofield.is_some() { 1u64 } else { 0u64 })*;
                e.map(required_entries + optional_entries)?;

                $(
                    e.str($rkey)?;
                    e.encode(&self.$rfield)?;
                )*

                $(
                    if let Some(value) = &self.$ofield {
                        e.str($okey)?;
                        e.encode(value)?;
                    }
                )*

                Ok(())
            }
        }

        impl<'b, C> minicbor::decode::Decode<'b, C> for $name {
            fn decode(
                d: &mut minicbor::decode::Decoder<'b>,
                _ctx: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let entries = d.map()?.ok_or_else(|| {
                    minicbor::decode::Error::message(concat!(stringify!($name), " must be a definite-length map"))
                })?;

                $( let mut $rfield: Option<$rty> = None; )*
                $( let mut $ofield: Option<$oty> = None; )*

                for _ in 0..entries {
                    let key = d.str()?.to_string();
                    match key.as_str() {
                        $(
                        $rkey => {
                                $rfield = Some(d.decode::<$rty>()?);
                            }
                        )*
                        $(
                            $okey => {
                                $ofield = Some(d.decode::<$oty>()?);
                            }
                        )*
                        _ => d.skip()?,
                    }
                }

                Ok(Self {
                    $(
                        $rfield: $rfield.ok_or_else(|| {
                            minicbor::decode::Error::message(concat!(stringify!($name), " missing ", stringify!($rfield)))
                        })?,
                    )*
                    $( $ofield, )*
                })
            }
        }
    };
}

pub(crate) use cbor_string_map_struct;
