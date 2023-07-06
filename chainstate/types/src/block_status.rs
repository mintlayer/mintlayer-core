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

use bitvec::prelude::*;
use derive_more::Display;
use enum_iterator::Sequence;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serialization::{Decode, Encode, Error as CodecError, Input, Output};
use std::ops::Range;

/// Block validation steps are always performed in the same order, which is represented by this enum.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Sequence, FromPrimitive)]
pub enum BlockValidationStage {
    Unchecked,
    CheckBlockOk,
    FullyChecked,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Decode, Encode)]
pub struct BlockStatus(BlockStatusInternal);

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
        Self(BlockStatusInternal::new())
    }

    /// Advance the last successful validation stage to the specified value.
    /// Note that the stage can only be advanced one step at a time.
    pub fn advance_validation_stage_to(&mut self, new_stage: BlockValidationStage) {
        assert!(self.last_valid_stage().next() == Some(new_stage));
        self.set_last_valid_stage(new_stage);
    }

    pub fn last_valid_stage(&self) -> BlockValidationStage {
        let val = self.0.get_field(BlockStatusField::ValidationStage);
        BlockValidationStage::from_u64(val).expect("Corrupted BlockValidationStage")
    }

    // Note: it's better to keep this function private if possible.
    fn set_last_valid_stage(&mut self, stage: BlockValidationStage) {
        self.0.set_field(
            BlockStatusField::ValidationStage,
            stage as BlockStatusEffectiveType,
        );
    }

    pub fn is_fully_valid(&self) -> bool {
        self.last_valid_stage() == BlockValidationStage::FullyChecked && self.is_ok()
    }

    pub fn is_ok(&self) -> bool {
        !(self.validation_failed() || self.has_invalid_parent())
    }

    pub fn set_validation_failed(&mut self) {
        self.0.set_flag(BlockStatusField::ValidationFailedBit, true);
    }

    pub fn validation_failed(&self) -> bool {
        self.0.get_flag(BlockStatusField::ValidationFailedBit)
    }

    pub fn set_has_invalid_parent(&mut self) {
        self.0.set_flag(BlockStatusField::InvalidParentBit, true);
    }

    pub fn has_invalid_parent(&self) -> bool {
        self.0.get_flag(BlockStatusField::InvalidParentBit)
    }

    // Note: this is needed for testing only.
    pub fn reserved_bits(&self) -> BlockStatusEffectiveType {
        self.0.get_field(BlockStatusField::ReservedArea1)
            | self.0.get_field(BlockStatusField::ReservedArea2)
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

// Each value here represents the bit number where the corresponding field starts.
#[derive(Sequence, Clone, Copy)]
enum BlockStatusField {
    ValidationStage = 0,
    ReservedArea1 = 8,
    ValidationFailedBit = 56,
    InvalidParentBit = 57,
    ReservedArea2,
    End = 64,
}

const BLOCK_STATUS_BIT_LEN: usize = BlockStatusField::End as usize;
type BlockStatusEffectiveType = u64;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct BlockStatusInternal(BitArr!(for BLOCK_STATUS_BIT_LEN, in u8, Lsb0));

impl BlockStatusInternal {
    fn from_num(value: BlockStatusEffectiveType) -> BlockStatusInternal {
        let mut array = BitArray::ZERO;
        array[0..BLOCK_STATUS_BIT_LEN].store(value);
        BlockStatusInternal(array)
    }

    fn new() -> BlockStatusInternal {
        BlockStatusInternal(BitArray::ZERO)
    }

    fn range_of(field: BlockStatusField) -> Range<usize> {
        field as usize..field.next().expect("Can't determine field's end") as usize
    }

    fn set_field(&mut self, field: BlockStatusField, val: BlockStatusEffectiveType) {
        self.set_bit_range(Self::range_of(field), val);
    }

    fn get_field(&self, field: BlockStatusField) -> BlockStatusEffectiveType {
        self.get_bit_range(Self::range_of(field))
    }

    fn set_flag(&mut self, field: BlockStatusField, val: bool) {
        let range = Self::range_of(field);
        assert!(range.len() == 1);
        self.set_bit_range(range, val as BlockStatusEffectiveType);
    }

    fn get_flag(&self, field: BlockStatusField) -> bool {
        let range = Self::range_of(field);
        assert!(range.len() == 1);
        self.get_bit_range(Self::range_of(field)) != 0
    }

    // Note: serialization will treat BlockStatusInternal an an opaque u64
    // (see implementations of Encode and Decode below), so when accessing bit ranges
    // we must specify endianness explicitly (i.e. use store_le/load_le instead of
    // just load/store).

    fn set_bit_range(&mut self, range: Range<usize>, val: BlockStatusEffectiveType) {
        assert!(range.end <= BLOCK_STATUS_BIT_LEN);
        // Note: "store" functions just truncate the input if it's too big.
        assert!(range.len() == BLOCK_STATUS_BIT_LEN || val < (1 << range.len()));
        self.0[range].store_le(val);
    }

    fn get_bit_range(&self, range: Range<usize>) -> BlockStatusEffectiveType {
        assert!(range.end <= BLOCK_STATUS_BIT_LEN);
        self.0[range].load_le()
    }
}

impl Encode for BlockStatusInternal {
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.load::<BlockStatusEffectiveType>().encode_to(dest)
    }
}

impl Decode for BlockStatusInternal {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        Ok(BlockStatusInternal::from_num(
            BlockStatusEffectiveType::decode(input)?,
        ))
    }
}
