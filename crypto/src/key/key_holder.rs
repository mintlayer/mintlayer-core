use serialization::{Decode, Encode};

use super::rschnorr::{MLRistrettoPrivateKey, MLRistrettoPublicKey};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum PrivateKeyHolder {
    RistrettoSchnorr(MLRistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum PublicKeyHolder {
    RistrettoSchnorr(MLRistrettoPublicKey),
}
