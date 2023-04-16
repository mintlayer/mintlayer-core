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

use chainstate_types::BlockIndex;
use common::{
    chain::Block,
    primitives::{BlockHeight, Id},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransactionSource {
    Chain(Id<Block>),
    Mempool,
}

impl<'a> From<&TransactionSourceForConnect<'a>> for TransactionSource {
    fn from(t: &TransactionSourceForConnect) -> Self {
        match t {
            TransactionSourceForConnect::Chain { new_block_index } => {
                TransactionSource::Chain(*new_block_index.block_id())
            }
            TransactionSourceForConnect::Mempool { current_best: _ } => TransactionSource::Mempool,
        }
    }
}

pub enum TransactionSourceForConnect<'a> {
    Chain { new_block_index: &'a BlockIndex },
    Mempool { current_best: &'a BlockIndex },
}

impl<'a> TransactionSourceForConnect<'a> {
    /// The block height of the transaction to be connected
    /// For the mempool, it's the height of the next-to-be block
    /// For the chain, it's for the block being connected
    pub fn expected_block_height(&self) -> BlockHeight {
        match self {
            TransactionSourceForConnect::Chain { new_block_index } => {
                new_block_index.block_height()
            }
            TransactionSourceForConnect::Mempool {
                current_best: best_block_index,
            } => best_block_index.block_height().next_height(),
        }
    }

    pub fn chain_block_index(&self) -> Option<&BlockIndex> {
        match self {
            TransactionSourceForConnect::Chain { new_block_index } => Some(new_block_index),
            TransactionSourceForConnect::Mempool { current_best: _ } => None,
        }
    }
}
