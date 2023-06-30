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

use bitflags::bitflags;
use derive_more::Display;
use enum_iterator::Sequence;
use serialization::{Decode, Encode};

// FIXME: which repr should I specify for the enums?
// (Also, can changing the repr in the future lead to incompatibilities with the existing DB?).

/// Block validation steps are always performed in the same order, which is represented by this enum.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Sequence, Decode, Encode)]
pub enum BlockValidationStage {
    Unchecked,
    CheckBlockOk,
    FullyChecked,
}

// FIXME: note that I'm using bitflags 1.x here. In 2.x they changed something and now Encode/Decode
// can't simply be derived for the struct. Is it OK to continue using bitflags 1.x?
// As a sidenote, I've also looked into several other "bit-flag" crates but they all seem to have
// their own drawbacks.
// The alternative is to follow the existing approach of Service/Services in
// "p2p/src/net/types/services.rs" or UtxoType/UtxoTypes in "wallet/types/src/utxo_types.rs",
// but I'd then try to generalize it first to avoid code duplication.
bitflags! {
    #[derive(Encode, Decode)]
    struct BlockStatusFlags: u8 {
        const DEFAULT = 0;

        const VALIDATION_FAILED = 1 << 0;
        const HAS_INVALID_PARENT = 1 << 1;

        const INVALID_FLAGS_MASK = Self::VALIDATION_FAILED.bits() | Self::HAS_INVALID_PARENT.bits();
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Decode, Encode)]
pub struct BlockStatus {
    last_valid_stage: BlockValidationStage,
    status_flags: BlockStatusFlags,
}

impl BlockStatus {
    pub const FULLY_CHECKED: BlockStatus = Self::new_at_stage(BlockValidationStage::FullyChecked);

    const fn new_at_stage(stage: BlockValidationStage) -> Self {
        Self {
            last_valid_stage: stage,
            status_flags: BlockStatusFlags::DEFAULT,
        }
    }

    pub const fn new() -> Self {
        Self::new_at_stage(BlockValidationStage::Unchecked)
    }

    /// Advance the last successful validation stage to the specified value.
    /// Note that the stage can only be advanced one step at a time.
    pub fn advance_validation_stage_to(&mut self, new_stage: BlockValidationStage) {
        assert!(self.last_valid_stage.next() == Some(new_stage));
        self.last_valid_stage = new_stage;
    }

    pub fn last_valid_stage(&self) -> BlockValidationStage {
        self.last_valid_stage
    }

    pub fn is_fully_valid(&self) -> bool {
        self.last_valid_stage == BlockValidationStage::FullyChecked && self.is_ok()
    }

    pub fn is_ok(&self) -> bool {
        (self.status_flags & BlockStatusFlags::INVALID_FLAGS_MASK).is_empty()
    }

    pub fn set_validation_failed(&mut self) {
        self.status_flags |= BlockStatusFlags::VALIDATION_FAILED;
    }

    pub fn validation_failed(&self) -> bool {
        !(self.status_flags & BlockStatusFlags::VALIDATION_FAILED).is_empty()
    }

    pub fn set_has_invalid_parent(&mut self) {
        self.status_flags |= BlockStatusFlags::HAS_INVALID_PARENT;
    }

    pub fn has_invalid_parent(&self) -> bool {
        !(self.status_flags & BlockStatusFlags::HAS_INVALID_PARENT).is_empty()
    }
}

impl std::fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockStatus(last_valid_stage: {}, status_flags: {})",
            self.last_valid_stage,
            self.status_flags.bits()
        )
    }
}
