use serialization_core::{Decode, Encode};

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum HexError {
    #[error("Scale codec decode error: {0}")]
    ScaleDecodeError(#[from] serialization_core::Error),
    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
}

pub trait HexEncode: Encode + Sized {
    fn hex_encode(&self) -> String {
        hex::encode(self.encode())
    }
}

pub trait HexDecode: Decode + Sized {
    fn hex_decode<T: AsRef<[u8]>>(data: T) -> Result<Self, HexError> {
        let unhexed = hex::decode(data)?;
        let decoded = Self::decode(&mut unhexed.as_slice())?;
        Ok(decoded)
    }
}
