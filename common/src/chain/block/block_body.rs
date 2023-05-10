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

use merkletree::MerkleTreeFormError;
use serialization::{Decode, Encode};

use crate::{chain::SignedTransaction, primitives::H256};

use super::{
    block_merkle::{calculate_tx_merkle_root, calculate_witness_merkle_root},
    BlockReward,
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockBody {
    pub(super) reward: BlockReward,
    pub(super) transactions: Vec<SignedTransaction>,
}

impl BlockBody {
    pub fn new(reward: BlockReward, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            reward,
            transactions,
        }
    }

    pub fn transactions(&self) -> &Vec<SignedTransaction> {
        &self.transactions
    }

    pub fn reward(&self) -> &BlockReward {
        &self.reward
    }

    pub fn tx_merkle_root(&self) -> Result<H256, MerkleTreeFormError> {
        calculate_tx_merkle_root(self)
    }

    pub fn witness_merkle_root(&self) -> Result<H256, MerkleTreeFormError> {
        calculate_witness_merkle_root(self)
    }
}
