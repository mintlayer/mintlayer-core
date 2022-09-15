use common::primitives::H256;
use serialization::{Decode, Encode};

pub mod error;
pub mod pool;
pub mod storage;

#[derive(Clone, Copy, Debug, Encode, Decode, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct PoolId(H256);

impl From<H256> for PoolId {
    fn from(h: H256) -> Self {
        Self(h)
    }
}

#[derive(Clone, Copy, Debug, Default, Encode, Decode, Eq, PartialEq, Ord, PartialOrd)]
pub struct DelegationId(H256);

impl From<H256> for DelegationId {
    fn from(h: H256) -> Self {
        Self(h)
    }
}
