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

pub mod config;
mod detail;
pub mod interface;
pub mod rpc;

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockCreationError},
        ChainConfig, GenBlock, PoolId, Transaction,
    },
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use config::BlockProdConfig;
use consensus::ConsensusCreationError;
use crypto::ephemeral_e2e;
use detail::{
    job_manager::{JobKey, JobManagerError},
    BlockProduction,
};
use interface::blockprod_interface::BlockProductionInterface;
use mempool::{tx_accumulator::TxAccumulatorError, MempoolHandle};
use p2p::P2pHandle;
use subsystem::error::CallError;

pub use detail::timestamp_searcher::{find_timestamps_for_staking, TimestampSearchData};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Failed to retrieve chainstate info")]
    ChainstateInfoRetrievalError,
    #[error("Wait for chainstate to sync before producing blocks")]
    ChainstateWaitForSync,
    #[error("Subsystem call error")]
    SubsystemCallError(#[from] CallError),
    #[error("Failed to add transaction {0}: {1}")]
    FailedToAddTransaction(Id<Transaction>, TxAccumulatorError),
    #[error("Block creation error: {0}")]
    FailedToConstructBlock(#[from] BlockCreationError),
    #[error("Initialization of consensus failed: {0}")]
    FailedConsensusInitialization(#[from] ConsensusCreationError),
    #[error("Block production cancelled")]
    Cancelled,
    #[error("Failed to retrieve peer count: {0}")]
    PeerCountRetrievalError(String),
    #[error("Connected peers {0} is below the required peer threshold {0}")]
    PeerCountBelowRequiredThreshold(usize, usize),
    #[error("Block not found in this round")]
    TryAgainLater,
    #[error("Job already exists")]
    JobAlreadyExists(JobKey),
    #[error("Job manager error: {0}")]
    JobManagerError(#[from] JobManagerError),
    #[error("Mempool failed to construct block: {0}")]
    MempoolBlockConstruction(#[from] mempool::error::BlockConstructionError),
    #[error("Failed to decrypt generate-block input data: {0}")]
    E2eError(#[from] ephemeral_e2e::error::Error),
    #[error("Overflowed when calculating a block timestamp: {0} + {1}")]
    TimestampOverflow(BlockTimestamp, u64),
    #[error("Chainstate error: `{0}`")]
    ChainstateError(#[from] consensus::ChainstateError),
    #[error("Wrong height range: {0}, {1}")]
    WrongHeightRange(BlockHeight, BlockHeight),
    #[error("Block at height {0} doesn't exist")]
    NoBlockForHeight(BlockHeight),
    #[error("Block index missing for block {0}")]
    InconsistentDbMissingBlockIndex(Id<GenBlock>),
    #[error("Unexpected consensus type: None")]
    UnexpectedConsensusTypeNone,
    #[error("Unexpected consensus type: PoW")]
    UnexpectedConsensusTypePoW,
    #[error("Pool data for pool {0} not found")]
    PoolDataNotFound(PoolId),
    #[error("Balance for pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] detail::utils::PoSAccountingError),
    #[error("PoS data provided when consensus is supposed to be ignored")]
    PoSInputDataProvidedWhenIgnoringConsensus,
    #[error("PoW data provided when consensus is supposed to be ignored")]
    PoWInputDataProvidedWhenIgnoringConsensus,
    #[error("Recoverable mempool error")]
    RecoverableMempoolError,
    #[error("Task exited prematurely")]
    TaskExitedPrematurely,
}

pub type BlockProductionSubsystem = Box<dyn BlockProductionInterface>;
pub type BlockProductionHandle = subsystem::Handle<dyn BlockProductionInterface>;

fn prepare_thread_pool(thread_count: u16) -> Arc<slave_pool::ThreadPool> {
    let mining_thread_pool = Arc::new(slave_pool::ThreadPool::new());
    mining_thread_pool
        .set_threads(thread_count)
        .expect("Event thread-pool starting failed");
    mining_thread_pool
}

pub fn make_blockproduction(
    chain_config: Arc<ChainConfig>,
    blockprod_config: Arc<BlockProdConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    p2p_handle: P2pHandle,
    time_getter: TimeGetter,
) -> Result<BlockProductionSubsystem, BlockProductionError> {
    // TODO: make the number of threads configurable
    let thread_count = 2;
    let mining_thread_pool = prepare_thread_pool(thread_count);

    let result = BlockProduction::new(
        chain_config,
        blockprod_config,
        chainstate_handle,
        mempool_handle,
        p2p_handle,
        time_getter,
        mining_thread_pool,
    )?;

    Ok(Box::new(result))
}

pub fn test_blockprod_config() -> BlockProdConfig {
    BlockProdConfig {
        min_peers_to_produce_blocks: 0,
        skip_ibd_check: false,
        use_current_time_if_non_pos: false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    use chainstate::{
        BlockIndex, BlockSource, ChainstateConfig, ChainstateHandle,
        DefaultTransactionVerificationStrategy,
    };
    use chainstate_storage::inmemory::Store;
    use common::{
        chain::{
            self,
            block::timestamp::BlockTimestamp,
            config::{create_unit_test_config, ChainConfig, ChainType},
            pos_initial_difficulty,
            stakelock::StakePoolData,
            Block, ConsensusUpgrade, Destination, Genesis, NetUpgrades, PoSChainConfigBuilder,
            TxOutput,
        },
        primitives::{per_thousand::PerThousand, Amount, BlockHeight, Idable, H256},
        time_getter::TimeGetter,
        Uint256, Uint512,
    };
    use consensus::{calculate_effective_pool_balance, compact_target_to_target};
    use crypto::{
        key::{KeyKind, PrivateKey},
        vrf::{VRFKeyKind, VRFPrivateKey},
    };
    use mempool::{MempoolConfig, MempoolHandle};
    use p2p::{
        peer_manager::peerdb::storage_impl::PeerDbStorageImpl, test_helpers::test_p2p_config,
    };
    use randomness::{CryptoRng, Rng};
    use storage_inmemory::InMemory;
    use subsystem::Manager;

    use super::*;

    pub async fn assert_process_block(
        chainstate: &ChainstateHandle,
        mempool: &MempoolHandle,
        new_block: Block,
    ) -> BlockIndex {
        let block_id = new_block.get_id();

        // Wait for mempool to be up-to-date with the new block. The subscriptions are not cleaned
        // up but hopefully it's not too bad just for testing.
        let (tip_sx, tip_rx) = tokio::sync::oneshot::channel();
        let tip_sx = utils::sync::Mutex::new(Some(tip_sx));
        mempool
            .call_mut(move |m| {
                m.subscribe_to_subsystem_events(Arc::new({
                    move |evt| match evt {
                        mempool::event::MempoolEvent::NewTip(tip) => {
                            if let Some(tip_sx) = tip_sx.lock().unwrap().take() {
                                assert_eq!(tip.block_id(), &block_id);
                                tip_sx.send(()).unwrap();
                            }
                        }
                        mempool::event::MempoolEvent::TransactionProcessed(_) => (),
                    }
                }))
            })
            .await
            .unwrap();

        let block_index = chainstate
            .call_mut(move |this| {
                let new_block_index = this
                    .process_block(new_block.clone(), BlockSource::Local)
                    .expect("Failed to process block")
                    .expect("Failed to activate best chain");

                assert_eq!(
                    new_block.header().header().block_id(),
                    *new_block_index.block_id(),
                    "The new block's Id is different to the new block index's block Id",
                );

                let best_block_index =
                    this.get_best_block_index().expect("Failed to get best block index");

                assert_eq!(
                    new_block_index.clone().into_gen_block_index().block_id(),
                    best_block_index.block_id(),
                    "The new block index not the best block index"
                );

                new_block_index
            })
            .await
            .expect("New block is not the new tip");

        tip_rx.await.unwrap();

        block_index
    }

    pub fn setup_blockprod_test(
        chain_config: Option<ChainConfig>,
        time_getter: TimeGetter,
    ) -> (
        Manager,
        Arc<ChainConfig>,
        ChainstateHandle,
        MempoolHandle,
        P2pHandle,
    ) {
        let manager_config =
            subsystem::ManagerConfig::new("blockprod-unit-test").enable_signal_handlers();
        let mut manager = Manager::new_with_config(manager_config);

        let chain_config = Arc::new(chain_config.unwrap_or_else(create_unit_test_config));

        let chainstate_config = ChainstateConfig {
            max_tip_age: Duration::from_secs(60 * 60 * 24 * 365 * 100).into(),
            // There is at least one long test in blockprod that gets significantly slowed down
            // by the heavy checks in chainstate. But since the checks are not very useful in blockprod
            // tests in general, we disable them globally.
            enable_heavy_checks: Some(false),

            max_db_commit_attempts: Default::default(),
            max_orphan_blocks: Default::default(),
            min_max_bootstrap_import_buffer_sizes: Default::default(),
            allow_checkpoints_mismatch: Default::default(),
        };

        let mempool_config = MempoolConfig::new();

        let chainstate = chainstate::make_chainstate(
            Arc::clone(&chain_config),
            chainstate_config,
            Store::new_empty().expect("Error initializing empty store"),
            DefaultTransactionVerificationStrategy::new(),
            None,
            time_getter.clone(),
        )
        .expect("Error initializing chainstate");

        let chainstate = manager.add_subsystem("chainstate", chainstate);

        let mempool = mempool::make_mempool(
            Arc::clone(&chain_config),
            mempool_config,
            subsystem::Handle::clone(&chainstate),
            time_getter.clone(),
        );
        let mempool = manager.add_custom_subsystem("mempool", |hdl| mempool.init(hdl));

        let mut p2p_config = test_p2p_config();
        p2p_config.bind_addresses = vec![SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into()];

        let p2p = p2p::make_p2p(
            true,
            Arc::clone(&chain_config),
            Arc::new(p2p_config),
            subsystem::Handle::clone(&chainstate),
            mempool.clone(),
            time_getter,
            PeerDbStorageImpl::new(InMemory::new()).unwrap(),
        )
        .expect("P2p initialization was successful")
        .add_to_manager("p2p", &mut manager);

        (manager, chain_config, chainstate, mempool, p2p)
    }

    pub fn make_genesis_timestamp(time_getter: &TimeGetter, rng: &mut impl Rng) -> BlockTimestamp {
        BlockTimestamp::from_int_seconds(
            (time_getter.get_time()
                - Duration::new(
                    // Genesis must be in the past: now - (1 day..2 weeks)
                    rng.gen_range(60 * 60 * 24..60 * 60 * 24 * 14),
                    0,
                ))
            .expect("No time underflow")
            .as_secs_since_epoch(),
        )
    }

    // Sanity check - ensure that the initial target is not too big, so that staking on top
    // of the genesis will actually need to advance the timestamp to succeed.
    pub fn ensure_reasonable_initial_target_for_pos_tests(
        chain_config: &ChainConfig,
        initial_target: &Uint256,
    ) {
        let min_stake_pool_pledge = chain_config.min_stake_pool_pledge();
        let final_suppply = chain_config.final_supply().unwrap().to_amount_atoms();

        let typical_test_pool_effective_balance: Uint512 = calculate_effective_pool_balance(
            min_stake_pool_pledge,
            min_stake_pool_pledge,
            final_suppply,
        )
        .unwrap()
        .into();

        let effective_target =
            (typical_test_pool_effective_balance * (*initial_target).into()).unwrap();
        assert!(
            effective_target <= (Uint256::MAX / Uint256::from_u64(2)).unwrap().into(),
            "Initial target is too big"
        );
    }

    pub fn create_genesis_for_pos_tests(
        timestamp: BlockTimestamp,
        extra_txs: &[TxOutput],
        rng: &mut (impl Rng + CryptoRng),
    ) -> (
        Genesis,
        /*stake_private_key:*/ PrivateKey,
        /*vrf_private_key:*/ VRFPrivateKey,
        /*create_pool_txoutput:*/ TxOutput,
    ) {
        let (stake_private_key, stake_public_key) =
            PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

        let (vrf_private_key, vrf_public_key) =
            VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);

        let create_pool_txoutput = {
            let min_stake_pool_pledge = {
                // throw away just to get value
                let chain_config = create_unit_test_config();
                chain_config.min_stake_pool_pledge()
            };

            TxOutput::CreateStakePool(
                H256::zero().into(),
                Box::new(StakePoolData::new(
                    min_stake_pool_pledge,
                    Destination::PublicKey(stake_public_key.clone()),
                    vrf_public_key,
                    Destination::PublicKey(stake_public_key),
                    PerThousand::new(1000).expect("Valid per thousand"),
                    Amount::ZERO,
                )),
            )
        };

        let mut txs = vec![create_pool_txoutput.clone()];
        txs.extend_from_slice(extra_txs);

        let genesis = Genesis::new("blockprod-testing".into(), timestamp, txs);

        (
            genesis,
            stake_private_key,
            vrf_private_key,
            create_pool_txoutput,
        )
    }

    pub fn setup_pos(
        time_getter: &TimeGetter,
        switch_to_pos_at: BlockHeight,
        extra_genesis_txs: &[TxOutput],
        rng: &mut (impl Rng + CryptoRng),
    ) -> (chain::config::Builder, PrivateKey, VRFPrivateKey, TxOutput) {
        let genesis_timestamp = make_genesis_timestamp(time_getter, rng);
        setup_pos_with_genesis_timestamp(
            genesis_timestamp,
            switch_to_pos_at,
            extra_genesis_txs,
            rng,
        )
    }

    pub fn setup_pos_with_genesis_timestamp(
        genesis_timestamp: BlockTimestamp,
        switch_to_pos_at: BlockHeight,
        extra_genesis_txs: &[TxOutput],
        rng: &mut (impl Rng + CryptoRng),
    ) -> (chain::config::Builder, PrivateKey, VRFPrivateKey, TxOutput) {
        let initial_target = pos_initial_difficulty(ChainType::Regtest);

        let (
            genesis,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = create_genesis_for_pos_tests(genesis_timestamp, extra_genesis_txs, rng);

        let net_upgrades = NetUpgrades::initialize(vec![
            (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
            (
                switch_to_pos_at,
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(initial_target.into()),
                    config: PoSChainConfigBuilder::new_for_unit_test().build(),
                },
            ),
        ])
        .expect("Net upgrades are valid");

        let chain_config_builder = chain::config::Builder::new(ChainType::Regtest)
            .genesis_custom(genesis)
            .consensus_upgrades(net_upgrades);

        (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        )
    }

    pub fn build_chain_config_for_pos(builder: chain::config::Builder) -> ChainConfig {
        let chain_config = builder.build();

        let first_pos_upgrade_difficulty = chain_config
            .consensus_upgrades()
            .all_upgrades()
            .iter()
            .find_map(|(_, upgrade)| match upgrade {
                ConsensusUpgrade::PoS {
                    initial_difficulty,
                    config: _,
                } => Some(initial_difficulty.unwrap()),
                ConsensusUpgrade::PoW { .. } | ConsensusUpgrade::IgnoreConsensus => None,
            })
            .unwrap();

        ensure_reasonable_initial_target_for_pos_tests(
            &chain_config,
            &compact_target_to_target(first_pos_upgrade_difficulty).unwrap(),
        );

        chain_config
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_make_blockproduction() {
        let time_getter = TimeGetter::default();
        let (mut manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, time_getter.clone());

        let blockprod = make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool.clone(),
            p2p.clone(),
            time_getter,
        )
        .expect("Error initializing blockprod");

        let blockprod = manager.add_direct_subsystem("blockprod", blockprod);
        let shutdown = manager.make_shutdown_trigger();

        tokio::spawn(async move {
            blockprod
                .call_async_mut(move |this| {
                    Box::pin(async move {
                        let stopped_jobs_count = this.stop_all().await;

                        assert_eq!(
                            stopped_jobs_count,
                            Ok(0),
                            "Failed to stop non-existent jobs"
                        );
                        shutdown.initiate();
                    })
                })
                .await
                .expect("Error initializing block production");
        });

        manager.main().await;
    }
}
