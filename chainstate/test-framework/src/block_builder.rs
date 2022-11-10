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

use std::collections::BTreeSet;

use crate::framework::BlockOutputs;
use crate::utils::{create_multiple_utxo_data, create_new_outputs, outputs_from_block};
use crate::TestFramework;
use chainstate::{BlockSource, ChainstateError};
use chainstate_types::BlockIndex;
use common::chain::OutPoint;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        signature::inputsig::InputWitness,
        signed_transaction::SignedTransaction,
        Block, GenBlock, Transaction, TxInput, TxOutput,
    },
    primitives::{Id, H256},
};
use crypto::random::{CryptoRng, Rng};
use itertools::Itertools;

/// The block builder that allows construction and processing of a block.
pub struct BlockBuilder<'f> {
    framework: &'f mut TestFramework,
    transactions: Vec<SignedTransaction>,
    prev_block_hash: Id<GenBlock>,
    timestamp: BlockTimestamp,
    consensus_data: ConsensusData,
    reward: BlockReward,
    block_source: BlockSource,
    used_utxo: BTreeSet<OutPoint>,
}

impl<'f> BlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
        let timestamp = BlockTimestamp::from_duration_since_epoch(framework.time_getter.get_time());
        let consensus_data = ConsensusData::None;
        let reward = BlockReward::new(Vec::new());
        let block_source = BlockSource::Local;
        let used_utxo = BTreeSet::new();

        Self {
            framework,
            transactions,
            prev_block_hash,
            timestamp,
            consensus_data,
            reward,
            block_source,
            used_utxo,
        }
    }

    /// Replaces the transactions.
    pub fn with_transactions(mut self, transactions: Vec<SignedTransaction>) -> Self {
        self.transactions = transactions;
        self
    }

    /// Appends the given transaction to the transactions list.
    pub fn add_transaction(mut self, transaction: SignedTransaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// Adds a transaction that uses random utxos
    pub fn add_test_transaction(mut self, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let utxo_set = self.framework.storage.read_utxo_set().unwrap();

        if !utxo_set.is_empty() {
            // TODO: get n utxos as inputs and create m new outputs
            let index = rng.gen_range(0..utxo_set.len());
            let (outpoint, utxo) = utxo_set.iter().nth(index).unwrap();
            if !self.used_utxo.contains(outpoint) {
                let new_utxo_data = create_multiple_utxo_data(
                    &self.framework.chainstate,
                    outpoint.tx_id(),
                    outpoint.output_index() as usize,
                    utxo.output(),
                    rng,
                );

                if let Some((witness, input, output)) = new_utxo_data {
                    self.used_utxo.insert(outpoint.clone());
                    return self.add_transaction(
                        SignedTransaction::new(
                            Transaction::new(0, vec![input], output, 0).unwrap(),
                            vec![witness],
                        )
                        .expect("invalid witness count"),
                    );
                }
            }
        }
        self
    }

    /// Adds a transaction that uses the transactions from the best block as inputs and
    /// produces new outputs.
    pub fn add_test_transaction_from_best_block(self, rng: &mut impl Rng) -> Self {
        let parent = self.framework.best_block_id();
        self.add_test_transaction_with_parent(parent, rng)
    }

    /// Same as `add_test_transaction_from_best_block`, but with a custom parent.
    pub fn add_test_transaction_with_parent(
        self,
        parent: Id<GenBlock>,
        rng: &mut impl Rng,
    ) -> Self {
        let (witnesses, inputs, outputs) =
            self.make_test_inputs_outputs(self.framework.outputs_from_genblock(parent), rng);
        self.add_transaction(
            SignedTransaction::new(Transaction::new(0, inputs, outputs, 0).unwrap(), witnesses)
                .expect("invalid witness count"),
        )
    }

    /// Same as `add_test_transaction_with_parent`, but uses reference to a block.
    pub fn add_test_transaction_from_block(self, parent: &Block, rng: &mut impl Rng) -> Self {
        let (witnesses, inputs, outputs) =
            self.make_test_inputs_outputs(outputs_from_block(parent), rng);
        self.add_transaction(
            SignedTransaction::new(Transaction::new(0, inputs, outputs, 0).unwrap(), witnesses)
                .expect("invalid witness count"),
        )
    }

    /// Adds a transaction that tries to spend the already spent output from the specified block.
    pub fn add_double_spend_transaction(
        mut self,
        parent: Id<GenBlock>,
        spend_from: Id<Block>,
        rng: &mut impl Rng,
    ) -> Self {
        let parent_outputs = self.framework.outputs_from_genblock(parent);
        let (mut witnesses, mut inputs, outputs) =
            self.make_test_inputs_outputs(parent_outputs, rng);
        let spend_from = self.framework.outputs_from_genblock(spend_from.into());
        inputs.push(TxInput::new(spend_from.keys().next().unwrap().clone(), 0));
        witnesses.push(InputWitness::NoSignature(None));
        self.transactions.push(
            SignedTransaction::new(Transaction::new(0, inputs, outputs, 0).unwrap(), witnesses)
                .expect("invalid witness count"),
        );
        self
    }

    /// Overrides the previous block hash that is deduced by default as the best block.
    pub fn with_parent(mut self, prev_block_hash: Id<GenBlock>) -> Self {
        self.prev_block_hash = prev_block_hash;
        self
    }

    /// Overrides the previous block hash by a random value making the resulting block an orphan.
    pub fn make_orphan(mut self, rng: &mut impl Rng) -> Self {
        self.prev_block_hash = Id::new(H256::random_using(rng));
        self
    }

    /// Overrides the timestamp that is equal to the current time by default.
    pub fn with_timestamp(mut self, timestamp: BlockTimestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Overrides the consensus data that is `ConsensusData::None` by default.
    pub fn with_consensus_data(mut self, data: ConsensusData) -> Self {
        self.consensus_data = data;
        self
    }

    /// Overrides the block reward that is empty by default.
    pub fn with_reward(mut self, reward: Vec<TxOutput>) -> Self {
        self.reward = BlockReward::new(reward);
        self
    }

    /// Builds a block without processing it.
    pub fn build(self) -> Block {
        Block::new(
            self.transactions,
            self.prev_block_hash,
            self.timestamp,
            self.consensus_data,
            self.reward,
        )
        .unwrap()
    }

    /// Constructs a block and processes it by the chainstate.
    pub fn build_and_process(self) -> Result<Option<BlockIndex>, ChainstateError> {
        let block = Block::new(
            self.transactions,
            self.prev_block_hash,
            self.timestamp,
            self.consensus_data,
            self.reward,
        )
        .unwrap();
        self.framework.process_block(block, self.block_source)
    }

    /// Produces a new set of inputs and outputs from the transactions of the specified block.
    fn make_test_inputs_outputs(
        &self,
        outputs: BlockOutputs,
        rng: &mut impl Rng,
    ) -> (Vec<InputWitness>, Vec<TxInput>, Vec<TxOutput>) {
        outputs
            .into_iter()
            .flat_map(|(s, o)| create_new_outputs(&self.framework.chainstate, s, &o, rng))
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip()
    }
}
