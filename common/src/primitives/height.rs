use parity_scale_codec_derive::{Decode, Encode};

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(u64);

const ZERO: BlockHeight = BlockHeight(0);
const ONE: BlockHeight = BlockHeight(1);
const MAX: BlockHeight = BlockHeight(u64::MAX);

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

    pub fn inner(self) -> u64 { self.0 }
}

pub trait Saturating<Rhs = Self> {
    fn saturating_sub(self, rhs: Rhs) -> Self;
    fn saturating_add(self, rhs: Rhs) -> Self;
    fn saturating_mul(self, rhs: Rhs) -> Self;
    // fn saturating_div(self, rhs: Rhs) -> Self;
}

impl Saturating<u64> for BlockHeight {
    fn saturating_sub(self, rhs: u64) -> Self {
        BlockHeight(self.0.saturating_sub(rhs))
    }

    fn saturating_add(self, rhs: u64) -> Self {
        BlockHeight(self.0.saturating_add(rhs))
    }

    fn saturating_mul(self, rhs: u64) -> Self {
        BlockHeight(self.0.saturating_mul(rhs))
    }

}

impl Saturating<BlockHeight> for BlockHeight {
    fn saturating_sub(self, rhs: BlockHeight) -> Self {
        self.saturating_sub(rhs.0)
    }

    fn saturating_add(self, rhs: BlockHeight) -> Self {
        self.saturating_add(rhs.0)
    }

    fn saturating_mul(self, rhs: BlockHeight) -> Self {
        self.saturating_mul(rhs.0)
    }
}