use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

pub enum SignatureKind {
    RistrettoSchnorr,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub(crate) enum SignatureHolder {
    RistrettoSchnorrSig(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct Signature {
    sig: SignatureHolder,
}

impl Signature {
    pub(crate) fn new(kind: SignatureKind, raw_sig: Vec<u8>) -> Self {
        let sig = match kind {
            SignatureKind::RistrettoSchnorr => SignatureHolder::RistrettoSchnorrSig(raw_sig),
        };
        Self { sig: sig }
    }

    pub fn is_aggregable(&self) -> bool {
        match self.sig {
            SignatureHolder::RistrettoSchnorrSig(_) => true,
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self.sig {
            SignatureHolder::RistrettoSchnorrSig(_) => SignatureKind::RistrettoSchnorr,
        }
    }

    pub fn raw(&self) -> Vec<u8> {
        match &self.sig {
            SignatureHolder::RistrettoSchnorrSig(v) => v.clone(),
        }
    }
}
