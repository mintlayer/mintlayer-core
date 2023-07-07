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

    pub fn is_fully_valid(&self) -> bool {
        self.last_valid_stage() == BlockValidationStage::FullyChecked && self.is_ok()
    }

    pub fn is_ok(&self) -> bool {
        !(self.validation_failed() || self.has_invalid_parent())
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

    // Note: this is needed for testing only.
    pub fn reserved_bits(&self) -> u64 {
        self.get_field(BlockStatusBitArea::ReservedArea)
    }

    fn bit_range_of(bits: BlockStatusBitArea) -> Range<usize> {
        bits as usize..bits.next().expect("Can't determine field's end") as usize
    }

    fn get_field(&self, bits: BlockStatusBitArea) -> u64 {
        let range = Self::bit_range_of(bits);
        let lsb_mask = (1 << range.len()) - 1;

        (self.0 >> range.start) & lsb_mask
    }

    fn set_field(&mut self, bits: BlockStatusBitArea, val: u64) {
        let range = Self::bit_range_of(bits);
        let lsb_mask = (1 << range.len()) - 1;
        let mask = lsb_mask << range.start;

        assert!(val <= lsb_mask);
        self.0 = (self.0 & !mask) | (val << range.start);
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

// Each value here represents the bit index where the corresponding field starts.
#[derive(Sequence, Clone, Copy)]
enum BlockStatusBitArea {
    ValidationStage = 0,
    ValidationFailedBit = 8,
    InvalidParentBit,
    ReservedArea,
    End = 64,
}
