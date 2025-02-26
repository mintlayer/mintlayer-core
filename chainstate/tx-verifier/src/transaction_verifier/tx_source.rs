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

use chainstate_types::{BlockIndex, GenBlockIndex};
use common::{
    chain::Block,
    primitives::{BlockHeight, Id},
};
use utxo::UtxoSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransactionSource {
    Chain(Id<Block>),
    Mempool,
}

impl From<&TransactionSourceWithHeight<'_>> for TransactionSource {
    fn from(t: &TransactionSourceWithHeight) -> Self {
        match t {
            TransactionSourceWithHeight::Chain { new_block_index } => {
                TransactionSource::Chain(*new_block_index.block_id())
            }
            TransactionSourceWithHeight::Mempool {
                current_best: _,
                effective_height: _,
            } => TransactionSource::Mempool,
        }
    }
}

/// A struct that represents the block height where that transaction is located.
/// When connecting a block, it's determined an unambiguous. For the mempool,
/// it's more complicated because it may either be for the possible next block,
/// or it might have some required tolerance for calculating the height, due
/// to timelocks depending on timestamps of blocks that haven't yet been created.
pub enum TransactionSourceWithHeight<'a> {
    Chain {
        new_block_index: &'a BlockIndex,
    },
    Mempool {
        /// Blockchain tip according to mempool
        current_best: &'a GenBlockIndex,
        /// Effective block height used for mempool transaction validation (e.g. timelocks)
        effective_height: BlockHeight,
    },
}

impl<'a> TransactionSourceWithHeight<'a> {
    pub fn for_chain(new_block_index: &'a BlockIndex) -> Self {
        Self::Chain { new_block_index }
    }

    /// Used for the transaction accumulator for block production,
    /// where the height of the new block is the current best + 1
    pub fn for_mempool(current_best: &'a GenBlockIndex) -> Self {
        let effective_height = current_best.block_height().next_height();
        Self::for_mempool_with_height(current_best, effective_height)
    }

    /// Source is mempool with given declared block height
    ///
    /// The height has to be strictly greater than the height of chain tip.
    /// This is used to specify the effective height freely when checking timelocks.
    /// This is needed when accepting new transactions to the mempool, where a certain
    /// tolerance to timelocks is needed due to fluctuations of block timestamps.
    pub fn for_mempool_with_height(
        current_best: &'a GenBlockIndex,
        effective_height: BlockHeight,
    ) -> Self {
        assert!(current_best.block_height() < effective_height);
        Self::Mempool {
            current_best,
            effective_height,
        }
    }

    /// The block height of the transaction to be connected
    ///
    /// * For the mempool, it's the height greater than tip, as specified by mempool
    /// * For the chain, it's for the block being connected
    pub fn expected_block_height(&self) -> BlockHeight {
        match self {
            TransactionSourceWithHeight::Chain { new_block_index } => {
                new_block_index.block_height()
            }
            TransactionSourceWithHeight::Mempool {
                current_best: _,
                effective_height,
            } => *effective_height,
        }
    }

    pub fn chain_block_index(&self) -> Option<&BlockIndex> {
        match self {
            TransactionSourceWithHeight::Chain { new_block_index } => Some(new_block_index),
            TransactionSourceWithHeight::Mempool {
                current_best: _,
                effective_height: _,
            } => None,
        }
    }

    pub fn to_utxo_source(&self) -> UtxoSource {
        match self {
            Self::Chain {
                new_block_index: idx,
            } => UtxoSource::Blockchain(idx.block_height()),
            Self::Mempool {
                current_best: _,
                effective_height: _,
            } => UtxoSource::Mempool,
        }
    }
}
