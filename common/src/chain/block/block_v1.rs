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

use serialization::{Decode, Encode};

use crate::{
    chain::{
        block::{Block, BlockReward, ConsensusData},
        transaction::Transaction,
    },
    primitives::{
        id::{self, Idable},
        Id, H256,
    },
};

use super::{block_header::BlockHeader, timestamp::BlockTimestamp};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serialization::Tagged)]
pub struct BlockV1 {
    pub(super) header: BlockHeader,
    pub(super) reward: BlockReward,
    pub(super) transactions: Vec<Transaction>,
}

impl Idable for BlockV1 {
    type Tag = Block;
    fn get_id(&self) -> Id<Block> {
        Id::new(id::hash_encoded(self.header()))
    }
}

impl BlockV1 {
    pub fn tx_merkle_root(&self) -> Option<H256> {
        self.header.tx_merkle_root
    }

    pub fn witness_merkle_root(&self) -> Option<H256> {
        self.header.witness_merkle_root
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        self.header.consensus_data = consensus_data;
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header.consensus_data
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.header.timestamp()
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn prev_block_id(&self) -> &Id<crate::chain::GenBlock> {
        &self.header.prev_block_id
    }

    pub fn block_reward_transactable(&self) -> () {
        // TODO: FIXME:
        todo!()
    }
}
