use parity_scale_codec_derive::{Decode, Encode};

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(u64);

const ZERO: BlockHeight = BlockHeight(0);
const ONE: BlockHeight = BlockHeight(1);
const MAX: BlockHeight = BlockHeight(u64::MAX);

// TODO: for discussion, comment from Lukas:
// https://github.com/mintlayer/mintlayer-core/pull/70#discussion_r793762390

impl BlockHeight {
    pub fn new(height: u64) -> BlockHeight {
        BlockHeight(height)
    }

    pub fn zero() -> BlockHeight {
        ZERO
    }

    pub fn one() -> BlockHeight {
        ONE
    }

    pub fn max() -> BlockHeight {
        MAX
    }

    pub fn inner(self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(BlockHeight::new)
    }
}
