use serialization::{Decode, Encode};

use crate::{chain::block::timestamp::BlockTimestamp, primitives::BlockHeight};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Encode, Decode)]
pub enum OutputTimeLock {
    #[codec(index = 0)]
    UntilHeight(BlockHeight),
    #[codec(index = 1)]
    UntilTime(BlockTimestamp),
    #[codec(index = 2)]
    ForBlockCount(#[codec(compact)] u64),
    #[codec(index = 3)]
    ForSeconds(#[codec(compact)] u64),
}
