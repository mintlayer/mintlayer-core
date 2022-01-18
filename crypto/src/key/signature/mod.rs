use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

pub enum SignatureKind {
    RistrettoSchnorr,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub enum Signature {
    #[codec(index = 0)]
    RistrettoSchnorrSig(Vec<u8>),
}

impl Signature {
    pub(crate) fn new(kind: SignatureKind, raw_sig: Vec<u8>) -> Self {
        match kind {
            SignatureKind::RistrettoSchnorr => Self::RistrettoSchnorrSig(raw_sig),
        }
    }

    pub fn is_aggregable(&self) -> bool {
        match self {
            Self::RistrettoSchnorrSig(_) => true,
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self {
            Self::RistrettoSchnorrSig(_) => SignatureKind::RistrettoSchnorr,
        }
    }

    pub fn raw(&self) -> Vec<u8> {
        match self {
            Self::RistrettoSchnorrSig(v) => v.clone(),
        }
    }
}
