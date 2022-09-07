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

use chainstate_storage::BlockchainStorageRead;
use common::{
    chain::{
        config::{Builder as ChainConfigBuilder, ChainType},
        signature::inputsig::InputWitness,
        tokens::OutputValue,
        Block, Destination, GenBlock, Genesis, NetUpgrades, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, Id, Idable},
};
use crypto::random::Rng;

use crate::{
    detail::{
        tests::{
            test_framework::{BlockBuilder, TestFrameworkBuilder, TransactionBuilder},
            TestBlockInfo,
        },
        BlockIndex, GenBlockIndex, TimeGetter,
    },
    BlockError, BlockHeight, BlockSource, ChainstateConfig,
};

/// The `Chainstate` wrapper that simplifies operations and checks in the tests.
pub struct TestFramework {
    pub chainstate: super::TestChainstate,
    pub block_indexes: Vec<BlockIndex>,
}

impl TestFramework {
    /// Creates a new test framework instance using a builder api.
    pub fn builder() -> TestFrameworkBuilder {
        TestFrameworkBuilder::new()
    }

    /// Returns a block builder instance that can be used for a block construction and processing.
    pub fn make_block_builder(&mut self) -> BlockBuilder {
        BlockBuilder::new(self)
    }

    /// Processes the given block.
    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let id = block.get_id();
        let index = self.chainstate.process_block(block, source)?;
        self.block_indexes.push(index.clone().unwrap_or_else(|| {
            self.chainstate.chainstate_storage.get_block_index(&id).unwrap().unwrap()
        }));
        Ok(index)
    }

    /// Creates and processes a given amount of blocks. Returns the id of the last produced block.
    ///
    /// Each block contains a single transaction that spends a random amount from the previous
    /// block outputs.
    pub fn create_chain(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks: usize,
        rng: &mut impl Rng,
    ) -> Result<Id<GenBlock>, BlockError> {
        // TODO: Instead of creating TestBlockInfo on every iteration, a proper UTXO set
        // abstraction should be used. See https://github.com/mintlayer/mintlayer-core/issues/312
        // for the details.
        let mut prev_block = TestBlockInfo::from_id(&self.chainstate, *parent_block);

        for _ in 0..blocks {
            let block = self
                .make_block_builder()
                // .with_transactions(vec![transaction])
                .add_test_transaction_with_parent(prev_block.id, rng)
                .with_parent(prev_block.id)
                .build();
            prev_block = TestBlockInfo::from_block(&block);
            self.process_block(block, BlockSource::Local)?;
        }

        Ok(prev_block.id)
    }

    /// Returns the genesis block of the chain.
    pub fn genesis(&self) -> &WithId<Genesis> {
        self.chainstate.chain_config.genesis_block()
    }

    /// Returns the best block index.
    #[track_caller]
    pub fn best_block_index(&self) -> GenBlockIndex {
        self.chainstate.query().get_best_block_index().unwrap().unwrap()
    }

    /// Return the best block identifier.
    #[track_caller]
    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_index().block_id()
    }

    /// Returns a test block information for the best block.
    #[track_caller]
    pub fn best_block_info(&self) -> TestBlockInfo {
        TestBlockInfo::from_id(&self.chainstate, self.best_block_id())
    }

    /// Returns a test block information for the specified height.
    #[track_caller]
    pub fn block_info(&self, height: u64) -> TestBlockInfo {
        let id = self
            .chainstate
            .query()
            .get_block_id_from_height(&BlockHeight::from(height))
            .unwrap()
            .unwrap();
        TestBlockInfo::from_id(&self.chainstate, id)
    }

    /// Returns a block corresponding to the specified identifier.
    #[track_caller]
    pub fn block(&self, id: Id<Block>) -> Block {
        self.chainstate.query().get_block(id).unwrap().unwrap()
    }

    /// Returns a block index corresponding to the specified id.
    pub fn block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.chainstate.make_db_tx_ro().get_gen_block_index(id).unwrap().unwrap()
    }

    pub fn index_at(&self, at: usize) -> &BlockIndex {
        assert!(at > 0, "No block index for genesis");
        &self.block_indexes[at - 1]
    }
}

impl Default for TestFramework {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[test]
fn build_test_framework() {
    let chain_type = ChainType::Mainnet;
    let max_db_commit_attempts = 10;

    let tf = TestFramework::builder()
        .with_chain_config(
            ChainConfigBuilder::new(chain_type)
                .net_upgrades(NetUpgrades::unit_tests())
                .genesis_unittest(Destination::AnyoneCanSpend)
                .build(),
        )
        .with_chainstate_config(ChainstateConfig {
            max_db_commit_attempts,
            ..Default::default()
        })
        .with_time_getter(TimeGetter::default())
        .build();

    assert_eq!(
        tf.chainstate.chainstate_config.max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(tf.chainstate.chain_config.chain_type(), &chain_type);
}

#[test]
fn process_block() {
    let mut tf = TestFramework::default();
    let outpoint_source_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();

    tf.make_block_builder()
        .add_transaction(
            TransactionBuilder::new()
                .add_input(TxInput::new(
                    outpoint_source_id,
                    0,
                    InputWitness::NoSignature(None),
                ))
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(0)),
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ))
                .build(),
        )
        .build_and_process()
        .unwrap();
}
