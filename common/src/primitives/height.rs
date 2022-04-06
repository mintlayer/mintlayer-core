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
        block_height.0
    }
}

impl From<HeightIntType> for BlockHeight {
    fn from(w: HeightIntType) -> BlockHeight {
        BlockHeight(w)
    }
}

impl Add<BlockDistance> for BlockHeight {
    type Output = Option<BlockHeight>;

    fn add(self, other: BlockDistance) -> Option<BlockHeight> {
        let height: i64 = self.0.try_into().ok()?;
        let result = height
            .checked_add(other.0)
            .expect("overflow when adding BlockHeight to instant");
        let result: u64 = result.try_into().ok()?;
        Some(Self(result))
    }
}

impl Sub<BlockDistance> for BlockHeight {
    type Output = Option<BlockHeight>;

    fn sub(self, other: BlockDistance) -> Option<BlockHeight> {
        let height: i64 = self.0.try_into().ok()?;

        if height < 0 {
            return None;
        }

        let raw_result: i64 = height.checked_sub(other.0)?;
        if raw_result < 0 {
            return None;
        }

        let raw_result: u64 = raw_result.try_into().ok()?;

        Some(BlockHeight::new(raw_result))
    }
}

impl Add<BlockDistance> for BlockDistance {
    type Output = Option<BlockDistance>;

    fn add(self, other: BlockDistance) -> Option<BlockDistance> {
        Some(BlockDistance(self.0.checked_add(other.0)?))
    }
}

impl Sub<BlockDistance> for BlockDistance {
    type Output = Option<BlockDistance>;

    fn sub(self, other: BlockDistance) -> Option<BlockDistance> {
        Some(BlockDistance(self.0.checked_sub(other.0)?))
    }
}

impl Sub<BlockHeight> for BlockHeight {
    type Output = Option<BlockDistance>;

    fn sub(self, other: BlockHeight) -> Option<BlockDistance> {
        let h1: i64 = self.0.try_into().ok()?;
        let h2: i64 = other.0.try_into().ok()?;

        Some(BlockDistance(h1.checked_sub(h2)?))
    }
}

impl BlockHeight {
    const ZERO: BlockHeight = BlockHeight(0);
    const ONE: BlockHeight = BlockHeight(1);
    const MAX: BlockHeight = BlockHeight(HeightIntType::MAX);

    pub fn new(height: HeightIntType) -> Self {
        Self(height)
    }

    pub fn zero() -> BlockHeight {
        BlockHeight::ZERO
    }

    pub fn one() -> BlockHeight {
        BlockHeight::ONE
    }

    pub fn max() -> BlockHeight {
        BlockHeight::MAX
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_arithmetic_low() {
        let h_5 = BlockHeight::new(5);
        let d_4 = BlockDistance::new(4);
        let d_5 = BlockDistance::new(5);
        let d_6 = BlockDistance::new(6);
        assert_eq!((h_5 - d_4).unwrap(), BlockHeight::new(1));
        assert_eq!((h_5 - d_5).unwrap(), BlockHeight::new(0));
        assert!((h_5 - d_6).is_none());

        assert_eq!((d_5 - d_4).unwrap(), BlockDistance::new(1));
        assert_eq!((d_5 - d_5).unwrap(), BlockDistance::new(0));
        assert_eq!((d_5 - d_6).unwrap(), BlockDistance::new(-1));

        assert_eq!((d_5 + d_4).unwrap(), BlockDistance::new(9));
        assert_eq!((d_5 + d_5).unwrap(), BlockDistance::new(10));
        assert_eq!((d_5 + d_6).unwrap(), BlockDistance::new(11));

        assert_eq!(BlockHeight::max() - BlockDistance::new(1), None);
        assert_eq!(BlockHeight::max() + BlockDistance::new(0), None);
        assert_eq!(BlockHeight::max() + BlockDistance::new(1), None);
    }

    #[test]
    fn basic_arithmetic_high() {
        let h_halfmax = BlockHeight::new(HeightIntType::MAX / 2);
        let d_max = BlockDistance::new(DistanceIntType::MAX);
        let d_m1 = BlockDistance::new(-1);
        let d_0 = BlockDistance::new(0);
        let d_p1 = BlockDistance::new(1);
        assert_eq!(
            (h_halfmax + d_m1).unwrap(),
            BlockHeight::new(HeightIntType::MAX / 2 - 1)
        );
        assert_eq!(
            (h_halfmax + d_0).unwrap(),
            BlockHeight::new(HeightIntType::MAX / 2)
        );
        assert_eq!(
            (d_max + d_m1).unwrap(),
            BlockDistance::new(DistanceIntType::MAX - 1)
        );
        assert_eq!(
            (d_max + d_0).unwrap(),
            BlockDistance::new(DistanceIntType::MAX)
        );
        assert!((d_max + d_p1).is_none());
    }

    #[test]
    #[should_panic]
    fn basic_arithmetic_hit_max() {
        let h_halfmax = BlockHeight::new(HeightIntType::MAX / 2);
        let d_p1 = BlockDistance::new(1);
        let _ = h_halfmax + d_p1;
    }
}
