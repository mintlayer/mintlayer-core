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
    key_manager::KeyManager,
    pos_block_builder::PoSBlockBuilder,
    random_tx_maker::StakingPoolsObserver,
    staking_pools::StakingPools,
    utils::{
        assert_block_index_opt_identical_to, assert_gen_block_index_identical_to,
        assert_gen_block_index_opt_identical_to, find_create_pool_tx_in_genesis,
        outputs_from_block, outputs_from_genesis,
    },
    BlockBuilder, TestChainstate, TestFrameworkBuilder, TestStore,
};
use chainstate::{chainstate_interface::ChainstateInterface, BlockSource, ChainstateError};
use chainstate_types::{BlockIndex, BlockStatus, GenBlockIndex};
use common::{
    chain::{
        Block, ChainConfig, GenBlock, GenBlockId, Genesis, OutPointSourceId, PoolId, TxOutput,
        UtxoOutPoint,
    },
    primitives::{id::WithId, time::Time, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use crypto::{key::PrivateKey, vrf::VRFPrivateKey};
use randomness::{CryptoRng, Rng};
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
    pub key_manager: KeyManager,
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
                .get_block_index_for_any_block(index.block_id())?
                .expect("Old block index must still be present");
        }

        Ok(())
    }

    fn do_process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let block_id = block.get_id();

        // Call block_index_opt/best_block_index unconditionally before and after process_block,
        // in order to perform the corresponding consistency checks.
        let orig_best_block_index = self.best_block_index();
        let orig_block_index_opt = self.block_index_opt(&block_id);
        let process_block_result = self.chainstate.process_block(block, source);
        let new_best_block_index = self.best_block_index();
        let new_block_index_opt = self.block_index_opt(&block_id);

        // Note: below we examine block indices but don't check for the existence of the block itself,
        // because this is redundant (the consistency check in best_block_index has already ensured
        // that a block can exist iff its block index has the persistence flag set).
        match process_block_result {
            Ok(block_index_result) => {
                let saved_index = new_block_index_opt.unwrap();
                assert!(saved_index.is_persisted());

                if let Some(returned_index) = &block_index_result {
                    assert_gen_block_index_identical_to(
                        &GenBlockIndex::Block(returned_index.clone()),
                        &new_best_block_index,
                    );
                } else {
                    assert_gen_block_index_identical_to(
                        &new_best_block_index,
                        &orig_best_block_index,
                    );
                }

                self.block_indexes.push(saved_index);
                Ok(block_index_result)
            }
            Err(err) => {
                let was_persisted =
                    orig_block_index_opt.as_ref().is_some_and(|idx| idx.is_persisted());
                let is_persisted =
                    new_block_index_opt.as_ref().is_some_and(|idx| idx.is_persisted());

                // If block was persisted, it should stay persisted.
                // On the other hand, failed process_block should not save a new block index with
                // persistence flag set.
                assert_eq!(was_persisted, is_persisted);

                if let Some(new_block_index) = &new_block_index_opt {
                    if orig_block_index_opt.is_none() {
                        assert!(!new_block_index.status().is_ok());
                    }
                }

                assert_gen_block_index_identical_to(&new_best_block_index, &orig_best_block_index);

                Err(err)
            }
        }
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
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Vec<Id<GenBlock>>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Vec<Id<GenBlock>>, ChainstateError> {
            let mut ids = Vec::with_capacity(blocks_count);
            for _ in 0..blocks_count {
                let block = self
                    .make_block_builder()
                    .add_test_transaction_with_parent(prev_block_id, rng)
                    .with_parent(prev_block_id)
                    .build(&mut *rng);
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
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Vec<Id<GenBlock>>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Vec<Id<GenBlock>>, ChainstateError> {
            let mut ids = Vec::with_capacity(blocks_count);
            let target_block_time = self.chain_config().target_block_spacing();
            for _ in 0..blocks_count {
                self.progress_time_seconds_since_epoch(target_block_time.as_secs());
                let block = self
                    .make_block_builder()
                    .add_test_transaction_with_parent(prev_block_id, rng)
                    .with_parent(prev_block_id)
                    .build(rng);
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
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Id<GenBlock>, ChainstateError> {
        Ok(*self.create_chain_return_ids(parent_block, blocks_count, rng)?.last().unwrap())
    }

    pub fn create_chain_pos(
        &mut self,
        rng: &mut (impl Rng + CryptoRng),
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
                    .with_stake_pool_id(staking_pool)
                    .with_stake_spending_key(staking_sk.clone())
                    .with_vrf_key(staking_vrf_sk.clone())
                    .build(&mut *rng);
                prev_block_id = block.get_id().into();
                self.do_process_block(block, BlockSource::Local)?;
            }

            Ok(prev_block_id)
        }();

        self.refresh_block_indices()?;
        result
    }

    // Same as `create_chain` but blocks don't have txs. Useful when you want to trigger a reorg
    // but don't want utxos to be spent.
    pub fn create_chain_with_empty_blocks(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks_count: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Id<GenBlock>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        let result = || -> Result<Vec<Id<GenBlock>>, ChainstateError> {
            let mut ids = Vec::with_capacity(blocks_count);
            for _ in 0..blocks_count {
                let block = self.make_block_builder().with_parent(prev_block_id).build(&mut *rng);
                prev_block_id = block.get_id().into();
                ids.push(prev_block_id);
                self.do_process_block(block, BlockSource::Local)?;
            }

            Ok(ids)
        }()?;

        self.refresh_block_indices()?;
        Ok(*result.last().unwrap())
    }

    /// Returns the genesis block of the chain.
    pub fn genesis(&self) -> Arc<WithId<Genesis>> {
        self.chainstate.get_chain_config().genesis_block().clone()
    }

    /// Return the best block index, while doing some consistency checks.
    #[track_caller]
    pub fn best_block_index(&self) -> GenBlockIndex {
        let best_block_index = self.chainstate.get_best_block_index().unwrap();
        let best_block_id = self.chainstate.get_best_block_id().unwrap();
        assert_eq!(best_block_index.block_id(), best_block_id);
        assert!(self.chainstate.is_block_in_main_chain(&best_block_id).unwrap());
        best_block_index
    }

    /// Return the best block identifier.
    #[track_caller]
    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_index().block_id()
    }

    pub fn parent_block_id(&self, id: &Id<GenBlock>) -> Id<GenBlock> {
        self.gen_block_index(id).prev_block_id().expect("The block has no parent")
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

    /// Return a block given an id. Perform consistency checks.
    #[track_caller]
    pub fn block_opt(&self, id: Id<Block>) -> Option<Block> {
        self.check_block_index_consistency(&id.into());
        self.chainstate.get_block(id).unwrap()
    }

    /// Return a block given an id. Perform consistency checks.
    #[track_caller]
    pub fn block(&self, id: Id<Block>) -> Block {
        self.block_opt(id).unwrap()
    }

    /// Check consistency of block-index-related functions with respect to the given block id.
    /// Note: this is not the same as the db consistency checks that chainstate itself performs
    /// regularly, here we test what chainstate's functions return and the chainstate itself
    /// only checks the consistency of its db.
    fn check_block_index_consistency(&self, id: &Id<GenBlock>) {
        // First, check consistency of get_gen_block_index_for_any_block and get_gen_block_index_for_persisted_block.
        let any_gen_block_index_opt =
            self.chainstate.get_gen_block_index_for_any_block(id).unwrap();
        let persisted_gen_block_index_opt =
            self.chainstate.get_gen_block_index_for_persisted_block(id).unwrap();

        if any_gen_block_index_opt.as_ref().is_some_and(|idx| idx.is_persisted()) {
            assert_gen_block_index_opt_identical_to(
                persisted_gen_block_index_opt.as_ref(),
                any_gen_block_index_opt.as_ref(),
            );
        } else {
            assert_gen_block_index_opt_identical_to(persisted_gen_block_index_opt.as_ref(), None);
        }

        match id.classify(self.chain_config()) {
            GenBlockId::Block(ref id) => {
                // Now check consistency of get_block_index_for_any_block and get_block_index_for_persisted_block
                // as well as get_block_index_for_any_block and get_gen_block_index_for_any_block.
                // Also check that a block index has the persistence flag set iff the corresponding block data
                // is in the db (note that this part is somewhat redundant, because the chainstate consistency
                // checks also verify this; but this function will be called more often, so at least
                // it has a chance to catch a problem earlier).

                let any_block_index_opt =
                    self.chainstate.get_block_index_for_any_block(id).unwrap();
                let persisted_block_index_opt =
                    self.chainstate.get_block_index_for_persisted_block(id).unwrap();

                if any_block_index_opt.as_ref().is_some_and(|idx| idx.is_persisted()) {
                    assert_block_index_opt_identical_to(
                        persisted_block_index_opt.as_ref(),
                        any_block_index_opt.as_ref(),
                    );
                    assert!(self.chainstate.get_block(*id).unwrap().is_some());
                } else {
                    assert_block_index_opt_identical_to(persisted_block_index_opt.as_ref(), None);
                    assert!(self.chainstate.get_block(*id).unwrap().is_none());
                }

                let any_gen_block_index_opt2 =
                    any_block_index_opt.map(|idx| GenBlockIndex::Block(idx.clone()));
                assert_gen_block_index_opt_identical_to(
                    any_gen_block_index_opt2.as_ref(),
                    any_gen_block_index_opt.as_ref(),
                );
            }
            GenBlockId::Genesis(_) => {
                let any_gen_block_index = any_gen_block_index_opt.unwrap();
                assert_gen_block_index_identical_to(
                    &any_gen_block_index,
                    &GenBlockIndex::genesis(self.chain_config()),
                );
                assert!(any_gen_block_index.is_persisted());
            }
        }
    }

    /// Return a block index corresponding to the specified id; perform consistency checks.
    pub fn gen_block_index_opt(&self, id: &Id<GenBlock>) -> Option<GenBlockIndex> {
        self.check_block_index_consistency(id);
        self.chainstate.get_gen_block_index_for_any_block(id).unwrap()
    }

    /// Return a block index corresponding to the specified id; perform consistency checks.
    pub fn gen_block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.gen_block_index_opt(id).unwrap()
    }

    /// Return a block index corresponding to the specified id; perform consistency checks.
    pub fn block_index_opt(&self, id: &Id<Block>) -> Option<BlockIndex> {
        self.check_block_index_consistency(id.into());
        self.chainstate.get_block_index_for_any_block(id).unwrap()
    }

    /// Return a block index corresponding to the specified id; perform consistency checks.
    pub fn block_index(&self, id: &Id<Block>) -> BlockIndex {
        self.block_index_opt(id).unwrap()
    }

    pub fn block_index_exists(&self, id: &Id<GenBlock>) -> bool {
        self.gen_block_index_opt(id).is_some()
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

    pub fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
    ) {
        self.staking_pools.on_pool_created(pool_id, staker_key, vrf_sk, outpoint);
    }

    pub fn set_genesis_pool_keys(
        &mut self,
        pool_id: &PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
    ) {
        let outpoint = find_create_pool_tx_in_genesis(
            self.chainstate.get_chain_config().genesis_block(),
            pool_id,
        )
        .unwrap();
        self.on_pool_created(*pool_id, staker_key, vrf_sk, outpoint);
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
        .build_and_process(&mut rng)
        .unwrap();
}
