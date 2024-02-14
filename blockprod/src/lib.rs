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
pub mod detail;
pub mod interface;
pub mod rpc;

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{
    chain::{block::BlockCreationError, ChainConfig, GenBlock, Transaction},
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
    #[error("Failed to retrieve peer count")]
    PeerCountRetrievalError,
    #[error("Connected peers {0} is below the required peer threshold {0}")]
    PeerCountBelowRequiredThreshold(usize, usize),
    #[error("Block not found in this round")]
    TryAgainLater,
    #[error("Tip has changed. Stopping block production for previous tip {0} with height {1} to new tip {2} with height {3}")]
    TipChanged(Id<GenBlock>, BlockHeight, Id<GenBlock>, BlockHeight),
    #[error("Job already exists")]
    JobAlreadyExists(JobKey),
    #[error("Job manager error: {0}")]
    JobManagerError(#[from] JobManagerError),
    #[error("Mempool failed to construct block: {0}")]
    MempoolBlockConstruction(#[from] mempool::error::BlockConstructionError),
    #[error("Failed to decrypt generate-block input data: {0}")]
    E2eError(#[from] ephemeral_e2e::error::Error),
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
            block::timestamp::BlockTimestamp,
            config::{create_unit_test_config, Builder, ChainConfig, ChainType},
            pos_initial_difficulty,
            stakelock::StakePoolData,
            Block, ConsensusUpgrade, Destination, Genesis, NetUpgrades, PoSChainConfigBuilder,
            TxOutput,
        },
        primitives::{per_thousand::PerThousand, Amount, BlockHeight, Idable, H256},
        time_getter::TimeGetter,
    };
    use crypto::{
        key::{KeyKind, PrivateKey},
        random::Rng,
        vrf::{VRFKeyKind, VRFPrivateKey},
    };
    use mempool::{MempoolConfig, MempoolHandle};
    use p2p::{
        peer_manager::peerdb::storage_impl::PeerDbStorageImpl, testing_utils::test_p2p_config,
    };
    use storage_inmemory::InMemory;
    use subsystem::Manager;
    use test_utils::{
        mock_time_getter::mocked_time_getter_seconds,
        random::{make_seedable_rng, Seed},
    };
    use utils::atomics::SeqCstAtomicU64;

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
                m.subscribe_to_events(Arc::new({
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
        initial_mock_time: Option<Arc<SeqCstAtomicU64>>,
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

        let chainstate_config = {
            let mut chainstate_config = ChainstateConfig::new();
            chainstate_config.max_tip_age = Duration::from_secs(60 * 60 * 24 * 365 * 100).into();
            chainstate_config
        };
        let mempool_config = Arc::new(MempoolConfig::new());

        let time_getter = match initial_mock_time {
            Some(mock_time) => mocked_time_getter_seconds(mock_time),
            None => TimeGetter::default(),
        };

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

    pub fn setup_pos(seed: Seed) -> (ChainConfig, PrivateKey, VRFPrivateKey, TxOutput) {
        let mut rng = make_seedable_rng(seed);

        let (genesis_stake_private_key, genesis_stake_public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let (genesis_vrf_private_key, genesis_vrf_public_key) =
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let create_genesis_pool_txoutput = {
            let min_stake_pool_pledge = {
                // throw away just to get value
                let chain_config = create_unit_test_config();
                chain_config.min_stake_pool_pledge()
            };

            TxOutput::CreateStakePool(
                H256::zero().into(),
                Box::new(StakePoolData::new(
                    min_stake_pool_pledge,
                    Destination::PublicKey(genesis_stake_public_key.clone()),
                    genesis_vrf_public_key,
                    Destination::PublicKey(genesis_stake_public_key),
                    PerThousand::new(1000).expect("Valid per thousand"),
                    Amount::ZERO,
                )),
            )
        };

        let pos_chain_config = {
            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                BlockTimestamp::from_int_seconds(
                    (TimeGetter::default().get_time()
                        - Duration::new(
                            // Genesis must be in the past: now - (1 day..2 weeks)
                            rng.gen_range(60 * 60 * 24..60 * 60 * 24 * 14),
                            0,
                        ))
                    .expect("No time underflow")
                    .as_secs_since_epoch(),
                ),
                vec![create_genesis_pool_txoutput.clone()],
            );

            let net_upgrades = NetUpgrades::initialize(vec![
                (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
                (
                    BlockHeight::new(1),
                    ConsensusUpgrade::PoS {
                        initial_difficulty: Some(pos_initial_difficulty(ChainType::Regtest).into()),
                        config: PoSChainConfigBuilder::new_for_unit_test().build(),
                    },
                ),
            ])
            .expect("Net upgrades are valid");

            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis_block)
                .consensus_upgrades(net_upgrades)
                .build()
        };

        (
            pos_chain_config,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_make_blockproduction() {
        let (mut manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, None);

        let blockprod = make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool.clone(),
            p2p.clone(),
            Default::default(),
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
