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

use enum_iterator::Sequence;
use serialization::{Decode, Encode};

/// Block validation steps are always performed in the same order, which is represented by this enum.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Sequence, Decode, Encode)]
pub enum BlockValidationStage {
    Unchecked,
    ParentOk,
    CheckBlockOk,
    FullyChecked,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Decode, Encode)]
pub struct BlockStatus {
    last_successful_validation_stage: BlockValidationStage,
}

impl BlockStatus {
    pub const FULLY_CHECKED: BlockStatus = Self::new_at_stage(BlockValidationStage::FullyChecked);

    pub const fn new_at_stage(stage: BlockValidationStage) -> Self {
        Self {
            last_successful_validation_stage: stage,
        }
    }

    pub const fn new() -> Self {
        Self::new_at_stage(BlockValidationStage::Unchecked)
    }

    /// Advance the last successful validation stage to the specified value.
    /// Note that the stage can only be advanced one step at a time.
    pub fn advance_validation_stage_to(&mut self, new_stage: BlockValidationStage) {
        assert!(self.last_successful_validation_stage.next() == Some(new_stage));
        self.last_successful_validation_stage = new_stage;
    }

    pub fn is_valid(&self) -> bool {
        self.last_successful_validation_stage == BlockValidationStage::FullyChecked
    }

    pub fn last_valid_stage(&self) -> BlockValidationStage {
        self.last_successful_validation_stage
    }
}
