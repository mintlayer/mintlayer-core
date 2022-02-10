use crate::primitives::Compact;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum ConsensusData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    PoW(PoWData),
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct PoWData {
    bits: Compact,
    nonce: u128,
}
