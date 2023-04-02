use serialization_core::{Decode, DecodeAll, Encode};

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum HexError {
    #[error("Scale codec decode error: {0}")]
    ScaleDecodeError(#[from] serialization_core::Error),
    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
}

pub trait HexEncode: Encode + Sized {
    #[must_use]
    fn hex_encode(&self) -> String {
        hex::encode(self.encode())
    }
}

pub trait HexDecode: Decode + Sized {
    fn hex_decode_all<T: AsRef<str>>(data: T) -> Result<Self, HexError> {
        let unhexed = hex::decode(data.as_ref())?;
        let decoded = Self::decode_all(&mut unhexed.as_slice())?;
        Ok(decoded)
    }
}

impl<T: Encode + Sized> HexEncode for T {}
impl<T: Decode + Sized> HexDecode for T {}
