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

use std::{collections::BTreeMap, sync::Arc};

use chainstate_storage::{
    BlockchainStorageRead, BlockchainStorageWrite, TransactionRw, Transactional,
};
use rstest::rstest;

use crate::{
    pos_block_builder::PoSBlockBuilder,
    staking_pools::StakingPools,
    utils::{outputs_from_block, outputs_from_genesis},
    BlockBuilder, TestChainstate, TestFrameworkBuilder, TestStore,
};
use chainstate::{chainstate_interface::ChainstateInterface, BlockSource, ChainstateError};
use chainstate_types::{BlockIndex, BlockStatus, GenBlockIndex};
use common::{
    chain::{
        Block, ChainConfig, GenBlock, GenBlockId, Genesis, OutPointSourceId, PoolId, TxOutput,
    },
    primitives::{id::WithId, time::Time, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use crypto::{
    key::PrivateKey,
    random::{CryptoRng, Rng},
    vrf::VRFPrivateKey,
};
use utils::atomics::SeqCstAtomicU64;

/// The `Chainstate` wrapper that simplifies operations and checks in the tests.
#[must_use]
pub struct TestFramework {
    pub chainstate: TestChainstate,
    pub storage: TestStore,
    pub block_indexes: Vec<BlockIndex>,
    // A clone of the TimeGetter supplied to the chainstate
    pub time_getter: TimeGetter,
    // current time since epoch; if None, it means a custom TimeGetter was supplied and this is useless
    pub time_value: Option<Arc<SeqCstAtomicU64>>,

    // All pools from the tip that can be used for staking
    pub staking_pools: StakingPools,
}

pub type BlockOutputs = BTreeMap<OutPointSourceId, Vec<TxOutput>>;

impl TestFramework {
    /// Creates a new test framework instance using a builder api.
    pub fn builder(rng: &mut (impl Rng + CryptoRng)) -> TestFrameworkBuilder {
        TestFrameworkBuilder::new(rng)
    }

    pub fn reload(self) -> Self {
        TestFrameworkBuilder::from_existing_framework(self).build()
    }

    // TODO: remove this, because there is the 'into_chainstate' function below, which does the same.
    pub fn chainstate(self) -> TestChainstate {
        self.chainstate
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        self.chainstate.get_chain_config()
    }

    /// Returns a block builder instance that can be used for block construction and processing.
    pub fn make_block_builder(&mut self) -> BlockBuilder {
        BlockBuilder::new(self)
    }

    pub fn make_pos_block_builder(&mut self) -> PoSBlockBuilder {
        PoSBlockBuilder::new(self)
    }

    /// Get the current time using the time getter that was supplied to the test-framework
    pub fn current_time(&self) -> Time {
        self.time_getter.get_time()
    }

    /// The default TimeGetter of the test framework allows setting a custom time;
    /// this function increases the time value
    pub fn progress_time_seconds_since_epoch(&mut self, secs: u64) {
        match &self.time_value {
            Some(v) => v.fetch_add(secs),
            None => {
                panic!("Cannot progress time in TestFramework when custom time getter is supplied")
            }
        };
    }

    /// The default TimeGetter of the test framework allows setting a custom time;
    /// this function sets the time value to whatever is provided
    pub fn set_time_seconds_since_epoch(&mut self, val: u64) {
        match &self.time_value {
            Some(v) => v.store(val),
            None => {
                panic!("Cannot progress time in TestFramework when custom time getter is supplied")
            }
        };
    }

    // This function is supposed to be called after each process_block call to update the saved
    // block indices, which might have been invalidated.
    // Note that if it's called after each block creation inside functions that create lots
    // of blocks, like create_chain, it'll slow the tests down significantly, that's why we
    // have a separate private do_process_block, which doesn't call refresh_block_indices.
    fn refresh_block_indices(&mut self) -> Result<(), ChainstateError> {
        for index in &mut self.block_indexes {
            *index = self
                .chainstate
                .get_any_block_index(index.block_id())?
                .expect("Old block index must still be present");
        }

        Ok(())
    }

    fn do_process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let id = block.get_id();
        let block_index_result = self.chainstate.process_block(block, source)?;
        let index = match self.block_index(&id.into()) {
            GenBlockIndex::Genesis(..) => panic!("we have processed the genesis block"),
            GenBlockIndex::Block(block_index) => block_index,
        };
        self.block_indexes.push(index);

        Ok(block_index_result)
    }

    /// Processes the given block.
    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let result = self.do_process_block(block, source);
        self.refresh_block_indices()?;
        result
    }

    /// Create and process a given amount of blocks. Return the ids of the produced blocks.
    ///
    /// Each block contains a single transaction that spends a random amount from the previous
    /// block outputs.
    pub fn create_chain_return_ids(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks_count: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<Id<GenBlock>>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Vec<Id<GenBlock>>, ChainstateError> {
            let mut ids = Vec::new();
            for _ in 0..blocks_count {
                let block = self
                    .make_block_builder()
                    .add_test_transaction_with_parent(prev_block_id, rng)
                    .with_parent(prev_block_id)
                    .build();
                prev_block_id = block.get_id().into();
                ids.push(prev_block_id);
                self.do_process_block(block, BlockSource::Local)?;
            }

            Ok(ids)
        }();

        self.refresh_block_indices()?;
        result
    }

    /// Create and process a given amount of blocks. Return the ids of the produced blocks.
    ///
    /// Each block contains a single transaction that spends a random amount from the previous
    /// block outputs. Each block has an incremented timestamp
    pub fn create_chain_return_ids_with_advancing_time(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks_count: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<Id<GenBlock>>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Vec<Id<GenBlock>>, ChainstateError> {
            let mut ids = Vec::new();
            let target_block_time = self.chain_config().target_block_spacing();
            for _ in 0..blocks_count {
                self.progress_time_seconds_since_epoch(target_block_time.as_secs());
                let block = self
                    .make_block_builder()
                    .add_test_transaction_with_parent(prev_block_id, rng)
                    .with_parent(prev_block_id)
                    .build();
                prev_block_id = block.get_id().into();
                ids.push(prev_block_id);
                self.do_process_block(block, BlockSource::Local)?;
            }

            Ok(ids)
        }();

        self.refresh_block_indices()?;
        result
    }

    /// Same as `create_chain_return_ids`, but only return the id of the last produced block.
    pub fn create_chain(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks_count: usize,
        rng: &mut impl Rng,
    ) -> Result<Id<GenBlock>, ChainstateError> {
        Ok(*self.create_chain_return_ids(parent_block, blocks_count, rng)?.last().unwrap())
    }

    pub fn create_chain_pos(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks: usize,
        staking_pool: PoolId,
        staking_sk: &PrivateKey,
        staking_vrf_sk: &VRFPrivateKey,
    ) -> Result<Id<GenBlock>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Id<GenBlock>, ChainstateError> {
            for _ in 0..blocks {
                let block = self
                    .make_pos_block_builder()
                    .with_parent(prev_block_id)
                    .with_stake_pool(staking_pool)
                    .with_stake_spending_key(staking_sk.clone())
                    .with_vrf_key(staking_vrf_sk.clone())
                    .build();
                prev_block_id = block.get_id().into();
                self.do_process_block(block, BlockSource::Local)?;
            }

            Ok(prev_block_id)
        }();

        self.refresh_block_indices()?;
        result
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

    pub fn parent_block_id(&self, id: &Id<GenBlock>) -> Id<GenBlock> {
        self.block_index(id).prev_block_id().expect("The block has no parent")
    }

    /// Returns a block identifier for the specified height.
    #[track_caller]
    pub fn block_id(&self, height: u64) -> Id<GenBlock> {
        self.chainstate
            .get_block_id_from_height(&BlockHeight::from(height))
            .unwrap()
            .unwrap()
    }

    // TODO: make the functions below accept block Id's by ref.

    /// Returns the list of outputs from the selected block.
    #[track_caller]
    pub fn outputs_from_genblock(&self, id: Id<GenBlock>) -> BlockOutputs {
        match id.classify(self.chainstate.get_chain_config()) {
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

    /// Return the block index by block id. Ensure consistency of chainstate's get_any_gen_block_index
    /// and get_persistent_gen_block_index functions.
    pub fn block_index_opt(&self, id: &Id<GenBlock>) -> Option<GenBlockIndex> {
        let any_block_index_opt = self.chainstate.get_any_gen_block_index(id).unwrap();
        let persistent_block_index_opt =
            self.chainstate.get_persistent_gen_block_index(id).unwrap();

        if let Some(any_block_index) = &any_block_index_opt {
            if any_block_index.is_persistent() {
                assert_eq!(persistent_block_index_opt, any_block_index_opt);
            } else {
                assert_eq!(persistent_block_index_opt, None);
            }

            any_block_index_opt
        } else {
            assert_eq!(persistent_block_index_opt, None);
            None
        }
    }

    /// Returns a block index corresponding to the specified id.
    pub fn block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.block_index_opt(id).unwrap()
    }

    pub fn block_index_exists(&self, id: &Id<GenBlock>) -> bool {
        self.block_index_opt(id).is_some()
    }

    pub fn index_at(&self, at: usize) -> &BlockIndex {
        assert!(at > 0, "No block index for genesis");
        &self.block_indexes[at - 1]
    }

    /// Consumes a test framework and returns chainstate.
    pub fn into_chainstate(self) -> TestChainstate {
        self.chainstate
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> bool {
        self.chainstate.is_block_in_main_chain(&(*block_id).into()).unwrap()
    }

    pub fn to_chain_block_id(&self, block_id: &Id<GenBlock>) -> Id<Block> {
        block_id.classify(self.chainstate.get_chain_config()).chain_block_id().unwrap()
    }

    pub fn get_min_height_with_allowed_reorg(&self) -> BlockHeight {
        self.chainstate.get_min_height_with_allowed_reorg().unwrap()
    }

    pub fn set_block_status(&mut self, block_id: &Id<Block>, status: BlockStatus) {
        let mut block_idx = self
            .storage
            .transaction_ro()
            .unwrap()
            .get_block_index(block_id)
            .unwrap()
            .unwrap();
        block_idx.set_status(status);
        let mut tx_rw = self.storage.transaction_rw(None).unwrap();

        tx_rw.set_block_index(&block_idx).unwrap();
        tx_rw.commit().unwrap();
    }

    // Delete the block and its index
    pub fn purge_block(&mut self, block_id: &Id<Block>) {
        let mut tx_rw = self.storage.transaction_rw(None).unwrap();

        tx_rw.del_block(*block_id).unwrap();
        tx_rw.del_block_index(*block_id).unwrap();
        tx_rw.commit().unwrap();
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
                .consensus_upgrades(NetUpgrades::unit_tests())
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
            output_value::OutputValue, signature::inputsig::InputWitness, Destination, GenBlock,
            OutPointSourceId, TxInput, TxOutput,
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
                    TxInput::from_utxo(
                        OutPointSourceId::BlockReward(<Id<GenBlock>>::from(gen_block_id)),
                        0,
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(0)),
                    Destination::AnyoneCanSpend,
                ))
                .build(),
        )
        .build_and_process()
        .unwrap();
}
