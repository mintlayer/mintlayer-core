use crate::primitives::Compact;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ConsensusData {
    PoW(PoWData),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoWData {
    bits: Compact,
    nonce: u128,
}