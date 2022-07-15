// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chainstate_types::{block_index::BlockIndex, epoch_data::EpochData};
use common::{
    chain::block::Block,
    primitives::{BlockHeight, Id},
};

use crate::detail::PropertyQueryError;

pub trait BlockIndexHandle {
    fn get_block_index(
        &self,
        block_index: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError>;
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, PropertyQueryError>;
    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, PropertyQueryError>;
}
