// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use derive_more::Display;
use enum_iterator::Sequence;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serialization::{Decode, Encode};
use std::ops::Range;

/// Block validation steps are always performed in the same order, which is represented by this enum.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Sequence, FromPrimitive)]
pub enum BlockValidationStage {
    Unchecked,
    CheckBlockOk,
    FullyChecked,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Decode, Encode)]
pub struct BlockStatus(u64);

impl BlockStatus {
    pub fn new_at_stage(stage: BlockValidationStage) -> Self {
        let mut this = Self::new();
        this.set_last_valid_stage(stage);
        this
    }

    pub fn new_fully_checked() -> Self {
        Self::new_at_stage(BlockValidationStage::FullyChecked)
    }

    pub fn new() -> Self {
        Self(0)
    }

    /// Advance the last successful validation stage to the specified value.
    /// Note that the stage can only be advanced one step at a time.
    pub fn advance_validation_stage_to(&mut self, new_stage: BlockValidationStage) {
        assert!(self.last_valid_stage().next() == Some(new_stage));
        self.set_last_valid_stage(new_stage);
    }

    pub fn last_valid_stage(&self) -> BlockValidationStage {
        let val = self.get_field(BlockStatusBitArea::ValidationStage);
        BlockValidationStage::from_u64(val).expect("Corrupted BlockValidationStage")
    }

    // Note: it's better to keep this function private if possible.
    fn set_last_valid_stage(&mut self, stage: BlockValidationStage) {
        self.set_field(BlockStatusBitArea::ValidationStage, stage as u64)
    }

    /// Return true, if the block hasn't been marked as invalid *yet*.
    pub fn is_ok(&self) -> bool {
        self.get_bits(Self::bit_range_of_range(FAIL_BITS_RANGE)) == 0
    }

    /// Return true, if the block is actually valid.
    pub fn is_fully_valid(&self) -> bool {
        self.last_valid_stage() == BlockValidationStage::FullyChecked && self.is_ok()
    }

    pub fn set_validation_failed(&mut self) {
        self.set_field(BlockStatusBitArea::ValidationFailedBit, 1)
    }

    pub fn validation_failed(&self) -> bool {
        self.get_field(BlockStatusBitArea::ValidationFailedBit) != 0
    }

    pub fn set_has_invalid_parent(&mut self) {
        self.set_field(BlockStatusBitArea::InvalidParentBit, 1)
    }

    pub fn has_invalid_parent(&self) -> bool {
        self.get_field(BlockStatusBitArea::InvalidParentBit) != 0
    }

    pub fn set_explicitly_invalidated(&mut self) {
        self.set_field(BlockStatusBitArea::ExplicitlyInvalidatedBit, 1)
    }

    pub fn is_explicitly_invalidated(&self) -> bool {
        self.get_field(BlockStatusBitArea::ExplicitlyInvalidatedBit) != 0
    }

    pub fn with_cleared_fail_bits(&self) -> BlockStatus {
        let mut result = *self;
        result.set_bits(Self::bit_range_of_range(FAIL_BITS_RANGE), 0);
        result
    }

    #[cfg(test)]
    fn reserved_bits(&self) -> u64 {
        self.get_field(BlockStatusBitArea::ReservedArea)
    }

    fn bit_range_of(bits: BlockStatusBitArea) -> Range<usize> {
        bits as usize..bits.next().expect("Can't determine field's end") as usize
    }

    fn bit_range_of_range(range: Range<BlockStatusBitArea>) -> Range<usize> {
        range.start as usize..range.end as usize
    }

    fn get_field(&self, bits: BlockStatusBitArea) -> u64 {
        self.get_bits(Self::bit_range_of(bits))
    }

    fn set_field(&mut self, bits: BlockStatusBitArea, val: u64) {
        self.set_bits(Self::bit_range_of(bits), val);
    }

    fn get_bits(&self, bit_range: Range<usize>) -> u64 {
        assert!(!bit_range.is_empty() && bit_range.end <= 64);

        if bit_range.len() == 64 {
            self.0
        } else {
            let lsb_mask = (1 << bit_range.len()) - 1;
            (self.0 >> bit_range.start) & lsb_mask
        }
    }

    fn set_bits(&mut self, bit_range: Range<usize>, val: u64) {
        assert!(!bit_range.is_empty() && bit_range.end <= 64);

        self.0 = if bit_range.len() == 64 {
            val
        } else {
            let lsb_mask = (1 << bit_range.len()) - 1;
            let mask = lsb_mask << bit_range.start;
            assert!(val <= lsb_mask);
            (self.0 & !mask) | (val << bit_range.start)
        };
    }
}

impl std::fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockStatus({:#b})", self.0)
    }
}

// Each value here represents the bit index where the corresponding field starts; the end of the
// field will be the start of the next one. E.g. below "validation stage" will occupy bits [0, 8),
// "validation failed bit" will occupy bits [8, 9) (i.e. the single 8th bit) etc.
#[derive(Sequence, Clone, Copy)]
enum BlockStatusBitArea {
    ValidationStage = 0,
    ValidationFailedBit = 8,
    InvalidParentBit,
    ExplicitlyInvalidatedBit,
    ReservedArea,
    End = 64,
}

const FAIL_BITS_RANGE: Range<BlockStatusBitArea> = Range::<BlockStatusBitArea> {
    start: BlockStatusBitArea::ValidationFailedBit,
    end: BlockStatusBitArea::ReservedArea,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn test_bit_range_of() {
        assert_eq!(
            BlockStatus::bit_range_of(BlockStatusBitArea::ValidationStage),
            0..8
        );
        assert_eq!(
            BlockStatus::bit_range_of(BlockStatusBitArea::ValidationFailedBit),
            8..9
        );
        assert_eq!(
            BlockStatus::bit_range_of(BlockStatusBitArea::InvalidParentBit),
            9..10
        );
        assert_eq!(
            BlockStatus::bit_range_of(BlockStatusBitArea::ExplicitlyInvalidatedBit),
            10..11
        );
        assert_eq!(
            BlockStatus::bit_range_of(BlockStatusBitArea::ReservedArea),
            11..64
        );

        assert!(catch_unwind(|| BlockStatus::bit_range_of(BlockStatusBitArea::End)).is_err());
    }

    #[test]
    fn test_bit_range_of_range() {
        let small_range = Range::<BlockStatusBitArea> {
            start: BlockStatusBitArea::ValidationFailedBit,
            end: BlockStatusBitArea::ReservedArea,
        };

        assert_eq!(BlockStatus::bit_range_of_range(small_range), 8..11);

        let full_range = Range::<BlockStatusBitArea> {
            start: BlockStatusBitArea::ValidationStage,
            end: BlockStatusBitArea::End,
        };

        assert_eq!(BlockStatus::bit_range_of_range(full_range), 0..64);
    }

    #[allow(clippy::unusual_byte_groupings)]
    #[test]
    fn test_get_set_bits() {
        let mut status =
            BlockStatus(0b11110000_11001100_10101010_11100111_00011000_01010101_00110011_00001111);
        assert_eq!(
            status.get_bits(0..64),
            0b11110000_11001100_10101010_11100111_00011000_01010101_00110011_00001111
        );

        assert_eq!(
            status.get_bits(0..33),
            0b1_00011000_01010101_00110011_00001111
        );

        assert_eq!(
            status.get_bits(31..64),
            0b11110000_11001100_10101010_11100111_0
        );

        assert_eq!(
            status.get_bits(0..64),
            0b11110000_11001100_10101010_11100111_00011000_01010101_00110011_00001111
        );

        // Get empty range
        assert!(catch_unwind(|| status.get_bits(31..31)).is_err());

        // Get invalid range
        assert!(catch_unwind(|| status.get_bits(31..65)).is_err());

        status.set_bits(0..25, 0b1_11111111_11111111_11111111);
        assert_eq!(
            status.0,
            0b11110000_11001100_10101010_11100111_00011001_11111111_11111111_11111111
        );

        status.set_bits(20..32, 0b10101010_1010);
        assert_eq!(
            status.0,
            0b11110000_11001100_10101010_11100111_10101010_10101111_11111111_11111111
        );

        // Set empty range
        assert!(catch_unwind(AssertUnwindSafe(|| status.set_bits(31..31, 0))).is_err());
        assert_eq!(
            status.0,
            0b11110000_11001100_10101010_11100111_10101010_10101111_11111111_11111111
        );

        // Set invalid range
        assert!(catch_unwind(AssertUnwindSafe(|| status.set_bits(31..65, 0))).is_err());
        assert_eq!(
            status.0,
            0b11110000_11001100_10101010_11100111_10101010_10101111_11111111_11111111
        );

        // Set a value that is too big for the range.
        assert!(catch_unwind(AssertUnwindSafe(
            || status.set_bits(0..25, 0b11_11111111_11111111_11111111)
        ))
        .is_err());
        assert_eq!(
            status.0,
            0b11110000_11001100_10101010_11100111_10101010_10101111_11111111_11111111
        );
    }

    #[allow(clippy::unusual_byte_groupings)]
    #[test]
    fn test_get_field() {
        let pattern = 0b11110000_10101010_11001100;
        let status = BlockStatus(pattern);
        assert_eq!(status.0, pattern);
        assert_eq!(
            status.get_field(BlockStatusBitArea::ValidationStage),
            0b11001100
        );
        assert_eq!(status.get_field(BlockStatusBitArea::ValidationFailedBit), 0);
        assert_eq!(status.get_field(BlockStatusBitArea::InvalidParentBit), 1);
        assert_eq!(
            status.get_field(BlockStatusBitArea::ExplicitlyInvalidatedBit),
            0
        );
        assert_eq!(
            status.get_field(BlockStatusBitArea::ReservedArea),
            0b11110000_10101
        );

        let status = BlockStatus(pattern << 1);
        assert_eq!(status.0, pattern << 1);
        assert_eq!(
            status.get_field(BlockStatusBitArea::ValidationStage),
            0b10011000
        );
        assert_eq!(status.get_field(BlockStatusBitArea::ValidationFailedBit), 1);
        assert_eq!(status.get_field(BlockStatusBitArea::InvalidParentBit), 0);
        assert_eq!(
            status.get_field(BlockStatusBitArea::ExplicitlyInvalidatedBit),
            1
        );
        assert_eq!(
            status.get_field(BlockStatusBitArea::ReservedArea),
            0b11110000_101010
        );
    }

    #[allow(clippy::unusual_byte_groupings)]
    #[test]
    fn test_set_field() {
        let mut status = BlockStatus(0);
        assert_eq!(status.0, 0);

        status.set_field(BlockStatusBitArea::ValidationStage, 0b11001100);
        assert_eq!(status.0, 0b11001100);

        status.set_field(BlockStatusBitArea::ValidationFailedBit, 1);
        assert_eq!(status.0, 0b1_11001100);

        status.set_field(BlockStatusBitArea::InvalidParentBit, 1);
        assert_eq!(status.0, 0b11_11001100);

        status.set_field(BlockStatusBitArea::ExplicitlyInvalidatedBit, 1);
        assert_eq!(status.0, 0b111_11001100);

        status.set_field(
            BlockStatusBitArea::ReservedArea,
            0b10101010_10101010_10101010_10101010_10101010_10101010_10101,
        );
        assert_eq!(
            status.0,
            0b10101010_10101010_10101010_10101010_10101010_10101010_10101_111_11001100
        );
    }

    #[allow(clippy::unusual_byte_groupings)]
    #[test]
    fn test_set_field_panic_if_value_too_big() {
        assert!(catch_unwind(|| {
            let mut status = BlockStatus(0);
            status.set_field(BlockStatusBitArea::ValidationStage, 0b1_00000000);
        })
        .is_err());

        assert!(catch_unwind(|| {
            let mut status = BlockStatus(0);
            status.set_field(BlockStatusBitArea::ValidationFailedBit, 2);
        })
        .is_err());

        assert!(catch_unwind(|| {
            let mut status = BlockStatus(0);
            status.set_field(BlockStatusBitArea::InvalidParentBit, 2);
        })
        .is_err());

        assert!(catch_unwind(|| {
            let mut status = BlockStatus(0);
            status.set_field(BlockStatusBitArea::ExplicitlyInvalidatedBit, 2);
        })
        .is_err());

        assert!(catch_unwind(|| {
            let mut status = BlockStatus(0);
            status.set_field(
                BlockStatusBitArea::ReservedArea,
                // This is the value from test_set_field but with an additional 1 an the end.
                0b10101010_10101010_10101010_10101010_10101010_10101010_101011,
            );
        })
        .is_err());
    }

    #[test]
    fn test_default_state() {
        let status = BlockStatus::new();
        assert_eq!(status.last_valid_stage(), BlockValidationStage::Unchecked);
        assert!(status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_new_fully_checked() {
        let status = BlockStatus::new_fully_checked();
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(status.is_ok());
        assert!(status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_advance_validation_stage_to() {
        let mut status = BlockStatus::new();

        status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::CheckBlockOk
        );
        assert!(status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);

        status.advance_validation_stage_to(BlockValidationStage::FullyChecked);
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(status.is_ok());
        assert!(status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_set_validation_failed() {
        let mut status = BlockStatus::new_fully_checked();
        status.set_validation_failed();
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(!status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_set_has_invalid_parent() {
        let mut status = BlockStatus::new_fully_checked();
        status.set_has_invalid_parent();
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(!status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(status.has_invalid_parent());
        assert!(!status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_set_explicitly_invalidated() {
        let mut status = BlockStatus::new_fully_checked();
        status.set_explicitly_invalidated();
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(!status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(!status.validation_failed());
        assert!(!status.has_invalid_parent());
        assert!(status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_all_fail_bits() {
        let mut status = BlockStatus::new_fully_checked();
        status.set_validation_failed();
        status.set_has_invalid_parent();
        status.set_explicitly_invalidated();
        assert_eq!(
            status.last_valid_stage(),
            BlockValidationStage::FullyChecked
        );
        assert!(!status.is_ok());
        assert!(!status.is_fully_valid());
        assert!(status.validation_failed());
        assert!(status.has_invalid_parent());
        assert!(status.is_explicitly_invalidated());
        assert_eq!(status.reserved_bits(), 0);
    }

    #[test]
    fn test_with_cleared_fail_bits() {
        let mut status = BlockStatus::new_fully_checked();
        status.set_validation_failed();
        status.set_has_invalid_parent();
        status.set_explicitly_invalidated();

        assert!(!status.is_ok());
        assert!(status.validation_failed());
        assert!(status.has_invalid_parent());
        assert!(status.is_explicitly_invalidated());

        let new_status = status.with_cleared_fail_bits();
        assert!(new_status.is_ok());
        assert!(!new_status.validation_failed());
        assert!(!new_status.has_invalid_parent());
        assert!(!new_status.is_explicitly_invalidated());
    }
}
