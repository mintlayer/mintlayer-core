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

use common::{
    chain::{Block, TxMainChainIndex},
    primitives::id::WithId,
};

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a WithId<Block>, usize),
    BlockReward(&'a WithId<Block>),
}

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BlockTransactableWithIndexRef<'a> {
    Transaction(&'a WithId<Block>, usize, Option<TxMainChainIndex>),
    BlockReward(&'a WithId<Block>, Option<TxMainChainIndex>),
}

impl<'a> BlockTransactableWithIndexRef<'a> {
    pub fn without_tx_index(&self) -> BlockTransactableRef<'a> {
        match self {
            BlockTransactableWithIndexRef::Transaction(block, index, _) => {
                BlockTransactableRef::Transaction(block, *index)
            }
            BlockTransactableWithIndexRef::BlockReward(block, _) => {
                BlockTransactableRef::BlockReward(block)
            }
        }
    }

    pub fn take_tx_index(self) -> Option<TxMainChainIndex> {
        match self {
            BlockTransactableWithIndexRef::Transaction(_, _, idx) => idx,
            BlockTransactableWithIndexRef::BlockReward(_, idx) => idx,
        }
    }
}
