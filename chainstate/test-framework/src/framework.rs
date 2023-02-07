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

use crate::{
    utils::{outputs_from_block, outputs_from_genesis},
    BlockBuilder, TestFrameworkBuilder, TestStore,
};
use chainstate::{chainstate_interface::ChainstateInterface, BlockSource, ChainstateError};
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::{
    chain::{Block, GenBlock, GenBlockId, Genesis, OutPointSourceId, TxOutput},
    primitives::{id::WithId, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

/// The `Chainstate` wrapper that simplifies operations and checks in the tests.
pub struct TestFramework {
    pub chainstate: super::TestChainstate,
    pub storage: TestStore,
    pub block_indexes: Vec<BlockIndex>,
    // A clone of the TimeGetter supplied to the chainstate
    pub time_getter: TimeGetter,
    // current time since epoch; if None, it means a custom TimeGetter was supplied and this is useless
    pub time_value: Option<Arc<AtomicU64>>,
}

pub type BlockOutputs = BTreeMap<OutPointSourceId, Vec<TxOutput>>;

impl TestFramework {
    /// Creates a new test framework instance using a builder api.
    pub fn builder(rng: &mut (impl Rng + CryptoRng)) -> TestFrameworkBuilder {
        TestFrameworkBuilder::new(rng)
    }

    pub fn chainstate(self) -> super::TestChainstate {
        self.chainstate
    }

    /// Returns a block builder instance that can be used for block construction and processing.
    pub fn make_block_builder(&mut self) -> BlockBuilder {
        BlockBuilder::new(self)
    }

    /// Get the current time using the time getter that was supplied to the test-framework
    pub fn current_time(&self) -> Duration {
        self.time_getter.get_time()
    }

    /// The default TimeGetter of the test framework allows setting a custom time;
    /// this function increases the time value
    pub fn progress_time_seconds_since_epoch(&mut self, secs: u64) {
        match &self.time_value {
            Some(v) => v.fetch_add(secs, std::sync::atomic::Ordering::SeqCst),
            None => {
                panic!("Cannot progress time in TestFramework when custom time getter is supplied")
            }
        };
    }

    /// The default TimeGetter of the test framework allows setting a custom time;
    /// this function sets the time value to whatever is provided
    pub fn set_time_seconds_since_epoch(&mut self, val: u64) {
        match &self.time_value {
            Some(v) => v.store(val, std::sync::atomic::Ordering::SeqCst),
            None => {
                panic!("Cannot progress time in TestFramework when custom time getter is supplied")
            }
        };
    }

    /// Processes the given block.
    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let id = block.get_id();
        let block_index_result = self.chainstate.process_block(block, source)?;
        let index = match self.chainstate.get_gen_block_index(&id.into()).unwrap().unwrap() {
            GenBlockIndex::Genesis(..) => panic!("we have processed a block"),
            GenBlockIndex::Block(block_index) => block_index,
        };
        self.block_indexes.push(index);
        Ok(block_index_result)
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
    ) -> Result<Id<GenBlock>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        for _ in 0..blocks {
            let block = self
                .make_block_builder()
                .add_test_transaction_with_parent(prev_block_id, rng)
                .with_parent(prev_block_id)
                .build();
            prev_block_id = block.get_id().into();
            self.process_block(block, BlockSource::Local)?;
        }

        Ok(prev_block_id)
    }

    /// Returns the genesis block of the chain.
    pub fn genesis(&self) -> Arc<WithId<Genesis>> {
        self.chainstate.get_chain_config().genesis_block().clone()
    }

    /// Returns the best block index.
    #[track_caller]
    pub fn best_block_index(&self) -> GenBlockIndex {
        self.chainstate.get_best_block_index().unwrap()
    }

    /// Return the best block identifier.
    #[track_caller]
    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_index().block_id()
    }

    /// Returns a block identifier for the specified height.
    #[track_caller]
    pub fn block_id(&self, height: u64) -> Id<GenBlock> {
        self.chainstate
            .get_block_id_from_height(&BlockHeight::from(height))
            .unwrap()
            .unwrap()
    }

    /// Returns the list of outputs from the selected block.
    #[track_caller]
    pub fn outputs_from_genblock(&self, id: Id<GenBlock>) -> BlockOutputs {
        match id.classify(&self.chainstate.get_chain_config()) {
            GenBlockId::Genesis(_) => {
                outputs_from_genesis(self.chainstate.get_chain_config().genesis_block())
            }
            GenBlockId::Block(id) => {
                outputs_from_block(&self.chainstate.get_block(id).unwrap().unwrap())
            }
        }
    }

    /// Returns a block corresponding to the specified identifier.
    #[track_caller]
    pub fn block(&self, id: Id<Block>) -> Block {
        self.chainstate.get_block(id).unwrap().unwrap()
    }

    /// Returns a block index corresponding to the specified id.
    pub fn block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.chainstate.get_gen_block_index(id).unwrap().unwrap()
    }

    pub fn index_at(&self, at: usize) -> &BlockIndex {
        assert!(at > 0, "No block index for genesis");
        &self.block_indexes[at - 1]
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn build_test_framework(#[case] seed: test_utils::random::Seed) {
    use chainstate::ChainstateConfig;
    use common::chain::{
        config::{Builder as ChainConfigBuilder, ChainType},
        Destination, NetUpgrades,
    };
    use common::time_getter::TimeGetter;
    let chain_type = ChainType::Mainnet;
    let max_db_commit_attempts = 10;

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            ChainConfigBuilder::new(chain_type)
                .net_upgrades(NetUpgrades::unit_tests())
                .genesis_unittest(Destination::AnyoneCanSpend)
                .build(),
        )
        .with_chainstate_config(ChainstateConfig {
            max_db_commit_attempts: max_db_commit_attempts.into(),
            ..Default::default()
        })
        .with_time_getter(TimeGetter::default())
        .build();

    assert_eq!(
        *tf.chainstate.get_chainstate_config().max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(tf.chainstate.get_chain_config().chain_type(), &chain_type);
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn process_block(#[case] seed: test_utils::random::Seed) {
    use crate::TransactionBuilder;
    use common::{
        chain::{
            signature::inputsig::InputWitness, tokens::OutputValue, Destination, GenBlock,
            OutPointSourceId, OutputPurpose, TxInput, TxOutput,
        },
        primitives::{Amount, Id, Idable},
    };

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();
    let gen_block_id = tf.genesis().get_id();
    tf.make_block_builder()
        .add_transaction(
            TransactionBuilder::new()
                .add_input(
                    TxInput::new(
                        OutPointSourceId::BlockReward(<Id<GenBlock>>::from(gen_block_id)),
                        0,
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(0)),
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ))
                .build(),
        )
        .build_and_process()
        .unwrap();
}
