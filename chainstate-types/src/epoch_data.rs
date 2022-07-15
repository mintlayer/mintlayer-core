use common::primitives::H256;
use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Clone)]
pub struct EpochData {
    randomness: H256,
}
