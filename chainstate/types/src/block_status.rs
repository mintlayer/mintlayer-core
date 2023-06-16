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
use num_derive::ToPrimitive;
use utils::status::Statuses;

pub use utils::status::Status;

#[derive(Copy, Clone, Debug, Sequence, ToPrimitive)]
pub enum BlockStatusField {
    Ancestors,
    CheckBlock,
    BestChainActivation,
}

pub type BlockStatus = Statuses<1, BlockStatusField>;

pub const BLOCK_STATUS_ALL_GOOD: BlockStatus = BlockStatus::new_good();
