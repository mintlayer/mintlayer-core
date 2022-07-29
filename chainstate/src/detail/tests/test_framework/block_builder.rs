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
        signature::inputsig::InputWitness,
        Transaction, TxInput, TxOutput,
    },
    primitives::{time, Id, H256},
};
use crypto::random::Rng;

use crate::{
    detail::{
        tests::{create_new_outputs, test_framework::TestFramework, TestBlockInfo},
        BlockIndex,
    },
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
    /// Creates a new builder instance.
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

    /// Replaces the transactions.
    pub fn with_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    /// Appends the given transaction to the transactions list.
    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// Adds a transaction that uses the transactions from the previous block as inputs and
    /// produces new outputs.
    pub fn add_test_transaction(self, rng: &mut impl Rng) -> Self {
        let parent = self.framework.best_block_id();
        self.add_test_transaction_with_parent(parent, rng)
    }

    /// Same as `add_test_transaction`, but with a custom parent.
    pub fn add_test_transaction_with_parent(
        mut self,
        parent: Id<GenBlock>,
        rng: &mut impl Rng,
    ) -> Self {
        let (inputs, outputs): (Vec<_>, Vec<_>) = self.make_test_inputs_outputs(parent, rng);
        self.transactions.push(Transaction::new(0, inputs, outputs, 0).unwrap());
        self
    }

    /// Adds a transaction that tries to spend the already spent output from the specified block.
    pub fn add_double_spend_transaction(
        mut self,
        parent: Id<GenBlock>,
        spend_from: Id<Block>,
        rng: &mut impl Rng,
    ) -> Self {
        let (mut inputs, outputs): (Vec<_>, Vec<_>) = self.make_test_inputs_outputs(parent, rng);
        let spend_from = TestBlockInfo::from_id(&self.framework.chainstate, spend_from.into());
        inputs.push(TxInput::new(
            spend_from.txns[0].0.clone(),
            0,
            InputWitness::NoSignature(None),
        ));
        self.transactions.push(Transaction::new(0, inputs, outputs, 0).unwrap());
        self
    }

    /// Overrides the previous block hash that is deduced by default as the best block.
    pub fn with_parent(mut self, prev_block_hash: Id<GenBlock>) -> Self {
        self.prev_block_hash = prev_block_hash;
        self
    }

    /// Overrides the previous block hash by a random value making the resulting block an orphan.
    pub fn make_orphan(mut self) -> Self {
        self.prev_block_hash = Id::new(H256::random());
        self
    }

    /// Overrides the timestamp that is equal to the current time by default.
    pub fn with_timestamp(mut self, timestamp: BlockTimestamp) -> Self {
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
        self.framework.process_block(block, self.block_source)
    }

    /// Produces a new set of inputs and outputs from the transactions of the specified block.
    fn make_test_inputs_outputs(
        &self,
        parent: Id<GenBlock>,
        rng: &mut impl Rng,
    ) -> (Vec<TxInput>, Vec<TxOutput>) {
        TestBlockInfo::from_id(&self.framework.chainstate, parent)
            .txns
            .into_iter()
            .flat_map(|(s, o)| create_new_outputs(s, &o, rng))
            .unzip()
    }
}
