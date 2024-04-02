// Copyright (c) 2022 RBB S.r.l
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

use std::sync::Arc;

use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock, Genesis},
    primitives::{id::WithId, BlockHeight, Id, Idable},
    Uint256,
};

use crate::{BlockIndex, BlockStatus};

/// Generalized block index
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GenBlockIndex {
    Block(BlockIndex),
    Genesis(Arc<WithId<Genesis>>),
}

impl GenBlockIndex {
    pub fn block_id(&self) -> Id<GenBlock> {
        match self {
            GenBlockIndex::Block(b) => (*b.block_id()).into(),
            GenBlockIndex::Genesis(g) => g.get_id().into(),
        }
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        match self {
            GenBlockIndex::Block(b) => b.block_timestamp(),
            GenBlockIndex::Genesis(g) => g.timestamp(),
        }
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        match self {
            GenBlockIndex::Block(b) => b.chain_timestamps_max(),
            GenBlockIndex::Genesis(g) => g.timestamp(),
        }
    }

    pub fn block_height(&self) -> BlockHeight {
        match self {
            GenBlockIndex::Block(b) => b.block_height(),
            GenBlockIndex::Genesis(_g) => BlockHeight::zero(),
        }
    }

    pub fn chain_trust(&self) -> Uint256 {
        match self {
            GenBlockIndex::Block(b) => b.chain_trust(),
            GenBlockIndex::Genesis(_g) => Uint256::ZERO,
        }
    }

    pub fn prev_block_id(&self) -> Option<Id<GenBlock>> {
        match self {
            GenBlockIndex::Block(b) => Some(*b.prev_block_id()),
            GenBlockIndex::Genesis(..) => None,
        }
    }

    pub fn status(&self) -> BlockStatus {
        match self {
            GenBlockIndex::Block(b) => b.status(),
            GenBlockIndex::Genesis(..) => crate::block_status::BlockStatus::new_fully_checked(),
        }
    }

    pub fn is_persistent(&self) -> bool {
        match self {
            GenBlockIndex::Block(b) => b.is_persistent(),
            GenBlockIndex::Genesis(..) => true,
        }
    }

    pub fn chain_transaction_count(&self) -> u128 {
        match self {
            GenBlockIndex::Block(b) => b.chain_transaction_count(),
            GenBlockIndex::Genesis(_) => 0,
        }
    }
}

impl From<BlockIndex> for GenBlockIndex {
    fn from(bi: BlockIndex) -> Self {
        GenBlockIndex::Block(bi)
    }
}
