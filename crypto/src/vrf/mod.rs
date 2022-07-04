use parity_scale_codec::{Decode, Encode};

mod schnorrkel;

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum VRFKeyKind {
    Schnorrkel,
}

// #[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
// pub struct VRFPrivateKey {
//     key: VRFPrivateKeyHolder,
// }

// #[derive(PartialOrd, Ord, PartialEq, Eq, Clone, Decode, Encode)]
// pub enum VRFPublicKey {
//     Schnorrkel(schnorrkel::SchnorrkelPublicKey),
// }

// #[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
// pub(crate) enum VRFPrivateKeyHolder {
//     RistrettoSchnorr(schnorrkel::SchnorrkelPrivateKey),
// }
