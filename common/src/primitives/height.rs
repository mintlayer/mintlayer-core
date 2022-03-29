use parity_scale_codec_derive::{Decode, Encode};
use std::fmt;
use std::ops::{Add, Sub};

type HeightIntType = u64;
type DistanceIntType = i64;

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(HeightIntType);

// Display should be defined for thiserr crate
impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<BlockHeight> for HeightIntType {
    fn from(block_height: BlockHeight) -> HeightIntType {
        block_height.inner()
    }
}

impl From<HeightIntType> for BlockHeight {
    fn from(w: HeightIntType) -> BlockHeight {
        BlockHeight(w)
    }
}

impl Add<BlockDistance> for BlockHeight {
    type Output = Option<Self>;

    fn add(self, other: BlockDistance) -> Option<Self> {
        let height: i64 = self.0 as i64;
        if height < 0 {
            return None;
        }

        let result = height
            .checked_add(other.0)
            .expect("overflow when adding BlockHeight to instant");
        if result < 0 {
            return None;
        }

        let result = result as u64;
        Some(Self(result))
    }
}

impl Add<BlockDistance> for BlockDistance {
    type Output = Option<BlockDistance>;

    fn add(self, other: BlockDistance) -> Option<BlockDistance> {
        Some(BlockDistance(self.0.checked_add(other.0)?))
    }
}

impl Sub<BlockHeight> for BlockHeight {
    type Output = Option<BlockDistance>;

    fn sub(self, other: BlockHeight) -> Option<BlockDistance> {
        let h1 = self.0 as i64;
        let h2 = other.0 as i64;

        if h1 < 0 || h2 < 0 {
            return None;
        }

        Some(BlockDistance(h1.checked_sub(h2)?))
    }
}

const ZERO: BlockHeight = BlockHeight(0);
const ONE: BlockHeight = BlockHeight(1);
const MAX: BlockHeight = BlockHeight(HeightIntType::MAX);

impl BlockHeight {
    pub fn new(height: HeightIntType) -> Self {
        Self(height)
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

    pub fn inner(self) -> HeightIntType {
        self.0
    }

    pub fn checked_add(&self, rhs: HeightIntType) -> Option<Self> {
        self.0.checked_add(rhs).map(Self::new)
    }

    pub fn next_height(&self) -> BlockHeight {
        BlockHeight(self.0.checked_add(1).expect("Block height overflow"))
    }
}

/////////////////////////////

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockDistance(DistanceIntType);

impl BlockDistance {
    pub fn new(distance: DistanceIntType) -> Self {
        Self(distance)
    }
}

// Display should be defined for thiserr crate
impl fmt::Display for BlockDistance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<BlockDistance> for DistanceIntType {
    fn from(block_height: BlockDistance) -> DistanceIntType {
        block_height.0
    }
}

impl From<DistanceIntType> for BlockDistance {
    fn from(w: DistanceIntType) -> BlockDistance {
        BlockDistance(w)
    }
}
