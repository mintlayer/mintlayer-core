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
    const VALIDATION_STAGE_BITS: BitField = BitField::new(0, 8);

    const VALIDATION_FAILED_BIT: BitField = BitField::new(8, 1);
    const INVALID_PARENT_BIT: BitField = BitField::new(9, 1);

    const INVALID_FLAGS_MASK: u64 =
        Self::VALIDATION_FAILED_BIT.mask() | Self::INVALID_PARENT_BIT.mask();

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
        let val = Self::VALIDATION_STAGE_BITS.get_from(self.0);
        BlockValidationStage::from_u64(val).expect("Corrupted BlockValidationStage")
    }

    // Note: it's better to keep this function private if possible.
    fn set_last_valid_stage(&mut self, stage: BlockValidationStage) {
        self.0 = Self::VALIDATION_STAGE_BITS.set_to(self.0, stage as u64);
    }

    pub fn is_fully_valid(&self) -> bool {
        self.last_valid_stage() == BlockValidationStage::FullyChecked && self.is_ok()
    }

    pub fn is_ok(&self) -> bool {
        (self.0 & Self::INVALID_FLAGS_MASK) == 0
    }

    pub fn set_validation_failed(&mut self) {
        self.0 = Self::VALIDATION_FAILED_BIT.set_to(self.0, 1);
    }

    pub fn validation_failed(&self) -> bool {
        Self::VALIDATION_FAILED_BIT.get_from(self.0) != 0
    }

    pub fn set_has_invalid_parent(&mut self) {
        self.0 = Self::INVALID_PARENT_BIT.set_to(self.0, 1);
    }

    pub fn has_invalid_parent(&self) -> bool {
        Self::INVALID_PARENT_BIT.get_from(self.0) != 0
    }
}

impl std::fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockStatus(last_valid_stage: {}, validation_failed: {}, has_invalid_parent: {})",
            self.last_valid_stage(),
            self.validation_failed(),
            self.has_invalid_parent()
        )
    }
}

struct BitField {
    offset: usize,
    size: usize,
}

impl BitField {
    const fn new(offset: usize, size: usize) -> BitField {
        assert!(size != 0 && size < 64 && offset + size <= 64);
        BitField { offset, size }
    }

    // Mask for the bitfield as if its offset was 0.
    // This is also the maximum value of the bitfield.
    const fn lsb_mask(&self) -> u64 {
        (1 << self.size) - 1
    }

    const fn mask(&self) -> u64 {
        self.lsb_mask() << self.offset
    }

    pub const fn get_from(&self, storage: u64) -> u64 {
        (storage >> self.offset) & self.lsb_mask()
    }

    pub const fn set_to(&self, storage: u64, val: u64) -> u64 {
        assert!(val <= self.lsb_mask());
        (storage & !self.mask()) | (val << self.offset)
    }
}
