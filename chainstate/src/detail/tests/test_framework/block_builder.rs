// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common::{
    chain::{
        block::{timestamp::BlockTimestamp, ConsensusData},
        Transaction,
    },
    primitives::{time, Id},
};

use crate::{
    detail::{tests::test_framework::TestFramework, BlockIndex},
    Block, BlockError, BlockSource, GenBlock,
};

/// The block builder that allows construction and processing of a block.
pub struct BlockBuilder<'f> {
    framework: &'f mut TestFramework,
    transactions: Vec<Transaction>,
    prev_block_hash: Id<GenBlock>,
    timestamp: BlockTimestamp,
    consensus_data: ConsensusData,
    block_source: BlockSource,
}

impl<'f> BlockBuilder<'f> {
    pub fn new(framework: &'f mut TestFramework) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
        let timestamp = BlockTimestamp::from_duration_since_epoch(time::get());
        let consensus_data = ConsensusData::None;
        let block_source = BlockSource::Local;

        Self {
            framework,
            transactions,
            prev_block_hash,
            timestamp,
            consensus_data,
            block_source,
        }
    }

    pub fn with_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn with_prev_block_hash(mut self, prev_block_hash: Id<GenBlock>) -> Self {
        self.prev_block_hash = prev_block_hash;
        self
    }

    pub fn with_timestapm(mut self, timestamp: BlockTimestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Builds a block without processing it.
    pub fn build(self) -> Block {
        Block::new(
            self.transactions,
            self.prev_block_hash,
            self.timestamp,
            self.consensus_data,
        )
        .unwrap()
    }

    /// Constructs a block and processes it by the chainstate.
    pub fn process(self) -> Result<Option<BlockIndex>, BlockError> {
        let block = Block::new(
            self.transactions,
            self.prev_block_hash,
            self.timestamp,
            self.consensus_data,
        )
        .unwrap();
        self.framework.process_block(block.clone(), self.block_source)
    }
}
