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
    chain::{block::timestamp::BlockTimestamp, ChainConfig, GenBlock, Genesis},
    primitives::{id::WithId, BlockHeight, Id},
    Uint256,
};
use static_assertions::assert_not_impl_any;

use crate::{BlockIndex, BlockStatus};

/// Generalized block index
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GenBlockIndex {
    Block(BlockIndex),
    Genesis(Arc<WithId<Genesis>>),
}

impl GenBlockIndex {
    pub fn as_ref(&self) -> GenBlockIndexRef<'_> {
        match self {
            Self::Block(b) => GenBlockIndexRef::Block(b),
            Self::Genesis(g) => GenBlockIndexRef::Genesis(g),
        }
    }

    pub fn block_id(&self) -> Id<GenBlock> {
        *self.as_ref().block_id()
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        self.as_ref().block_timestamp()
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        self.as_ref().chain_timestamps_max()
    }

    pub fn block_height(&self) -> BlockHeight {
        self.as_ref().block_height()
    }

    pub fn chain_trust(&self) -> Uint256 {
        self.as_ref().chain_trust()
    }

    pub fn prev_block_id(&self) -> Option<Id<GenBlock>> {
        self.as_ref().prev_block_id().copied()
    }

    pub fn status(&self) -> BlockStatus {
        self.as_ref().status()
    }

    pub fn is_persisted(&self) -> bool {
        self.as_ref().is_persisted()
    }

    pub fn chain_transaction_count(&self) -> u128 {
        self.as_ref().chain_transaction_count()
    }

    pub fn genesis(chain_config: &ChainConfig) -> Self {
        Self::Genesis(Arc::clone(chain_config.genesis_block()))
    }

    /// Return true if all fields of this GenBlockIndex are exactly the same as other's.
    /// Note: same as in BlockIndex, we deliberately don't call this relation "equality".
    pub fn is_identical_to(&self, other: &GenBlockIndex) -> bool {
        match (self, other) {
            (Self::Block(b1), Self::Block(b2)) => b1.is_identical_to(b2),
            (Self::Genesis(g1), Self::Genesis(g2)) => {
                let eq = Arc::ptr_eq(g1, g2);
                debug_assert!(eq, "Attempt to compare different geneses");
                eq
            }
            (Self::Block(_), Self::Genesis(_)) | (Self::Genesis(_), Self::Block(_)) => false,
        }
    }
}

impl From<BlockIndex> for GenBlockIndex {
    fn from(bi: BlockIndex) -> Self {
        GenBlockIndex::Block(bi)
    }
}

/// Same as `GenBlockIndex`, but only holds a reference.
#[derive(Clone, Copy, Debug)]
pub enum GenBlockIndexRef<'a> {
    Block(&'a BlockIndex),
    Genesis(&'a WithId<Genesis>),
}

impl<'a> GenBlockIndexRef<'a> {
    pub fn block_id(&self) -> &Id<GenBlock> {
        match self {
            Self::Block(b) => b.block_id().into(),
            Self::Genesis(g) => WithId::id(g).into(),
        }
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        match self {
            Self::Block(b) => b.block_timestamp(),
            Self::Genesis(g) => g.timestamp(),
        }
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        match self {
            Self::Block(b) => b.chain_timestamps_max(),
            Self::Genesis(g) => g.timestamp(),
        }
    }

    pub fn block_height(&self) -> BlockHeight {
        match self {
            Self::Block(b) => b.block_height(),
            Self::Genesis(_g) => BlockHeight::zero(),
        }
    }

    pub fn chain_trust(&self) -> Uint256 {
        match self {
            Self::Block(b) => b.chain_trust(),
            Self::Genesis(_g) => Uint256::ZERO,
        }
    }

    pub fn prev_block_id(&self) -> Option<&Id<GenBlock>> {
        match self {
            Self::Block(b) => Some(b.prev_block_id()),
            Self::Genesis(..) => None,
        }
    }

    pub fn status(&self) -> BlockStatus {
        match self {
            Self::Block(b) => b.status(),
            Self::Genesis(..) => crate::block_status::BlockStatus::new_fully_checked(),
        }
    }

    pub fn is_persisted(&self) -> bool {
        match self {
            Self::Block(b) => b.is_persisted(),
            Self::Genesis(..) => true,
        }
    }

    pub fn chain_transaction_count(&self) -> u128 {
        match self {
            Self::Block(b) => b.chain_transaction_count(),
            Self::Genesis(_) => 0,
        }
    }
}

// Forbid implementing Eq and PartialEq for GenBlockIndex.
assert_not_impl_any!(GenBlockIndex: Eq, PartialEq);
assert_not_impl_any!(GenBlockIndexRef<'static>: Eq, PartialEq);
