use parity_scale_codec_derive::{Decode, Encode};
use std::ops::{Add, Mul, Sub};

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

    pub fn inner(self) -> u64 {
        self.0
    }

    pub fn checked_mul(&self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(BlockHeight::new)
    }

    pub fn checked_sub(&self, rhs: u64) -> Option<Self> {
        self.0.checked_sub(rhs).map(BlockHeight::new)
    }

    pub fn checked_add(&self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs).map(BlockHeight::new)
    }
}

impl Add<u64> for BlockHeight {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        BlockHeight::new(self.0 + rhs)
    }
}

impl Sub<u64> for BlockHeight {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        BlockHeight(self.0 - rhs)
    }
}

impl Mul<u64> for BlockHeight {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        BlockHeight(self.0 * rhs)
    }
}

impl Add<BlockHeight> for BlockHeight {
    type Output = Self;

    fn add(self, rhs: BlockHeight) -> Self::Output {
        self + rhs.0
    }
}

impl Sub<BlockHeight> for BlockHeight {
    type Output = Self;

    fn sub(self, rhs: BlockHeight) -> Self::Output {
        self - rhs.0
    }
}

impl Mul<BlockHeight> for BlockHeight {
    type Output = Self;

    fn mul(self, rhs: BlockHeight) -> Self::Output {
        self * rhs.0
    }
}
