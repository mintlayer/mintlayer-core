use parity_scale_codec_derive::{Decode, Encode};

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(u64);

const ZERO: BlockHeight = BlockHeight(0);
const ONE: BlockHeight = BlockHeight(1);

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
}

pub trait Saturating<Rhs = Self> {
    fn saturating_sub(self, rhs: Rhs) -> Self;
    fn saturating_add(self, rhs: Rhs) -> Self;
    fn saturating_mul(self, rhs: Rhs) -> Self;
    fn saturating_div(self, rhs: Rhs) -> Self;
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

    fn saturating_div(self, rhs: u64) -> Self {
        BlockHeight(self.0.saturating_div(rhs))
    }
}