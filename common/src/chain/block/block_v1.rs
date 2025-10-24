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

use serialization::{Decode, Encode};

use crate::{
    chain::{
        block::{Block, BlockReward, BlockRewardTransactable, ConsensusData},
        signed_transaction::SignedTransaction,
    },
    primitives::{id::Idable, Id, H256},
};

use super::{
    block_body::BlockBody, signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp,
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serialization::Tagged)]
pub struct BlockV1 {
    pub(super) header: SignedBlockHeader,
    pub(super) body: BlockBody,
}

impl Idable for BlockV1 {
    type Tag = Block;
    fn get_id(&self) -> Id<Block> {
        self.header().get_id()
    }
}

impl BlockV1 {
    pub fn tx_merkle_root(&self) -> H256 {
        self.header.header().tx_merkle_root
    }

    pub fn witness_merkle_root(&self) -> H256 {
        self.header.header().witness_merkle_root
    }

    pub fn header(&self) -> &SignedBlockHeader {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut SignedBlockHeader {
        &mut self.header
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header.header().consensus_data
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.header.header().timestamp()
    }

    pub fn transactions(&self) -> &[SignedTransaction] {
        &self.body.transactions
    }

    pub fn into_transactions(self) -> Vec<SignedTransaction> {
        self.body.transactions
    }

    pub fn prev_block_id(&self) -> &Id<crate::chain::GenBlock> {
        &self.header.header().prev_block_id
    }

    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    pub fn block_reward(&self) -> &BlockReward {
        &self.body.reward
    }

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable<'_> {
        let inputs = match &self.header.header().consensus_data {
            ConsensusData::None | ConsensusData::PoW(_) => None,
            ConsensusData::PoS(data) => Some(data.kernel_inputs()),
        };
        let witness = match &self.header.header().consensus_data {
            ConsensusData::None | ConsensusData::PoW(_) => None,
            ConsensusData::PoS(data) => Some(data.kernel_witness()),
        };

        BlockRewardTransactable::new(inputs, Some(self.body.reward.outputs()), witness)
    }
}
