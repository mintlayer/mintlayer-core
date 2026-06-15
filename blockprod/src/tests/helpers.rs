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

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use chainstate::{
    BlockIndex, BlockSource, ChainstateConfig, ChainstateHandle,
    DefaultTransactionVerificationStrategy,
};
use chainstate_storage::inmemory::Store;
use common::{
    Uint256, Uint512,
    chain::{
        self, Block, ConsensusUpgrade, Destination, Genesis, NetUpgrades, OutPointSourceId,
        PoSChainConfigBuilder, PoolId, SignedTransaction, TxInput, TxOutput,
        block::timestamp::BlockTimestamp,
        config::{ChainConfig, ChainType, create_unit_test_config},
        pos_initial_difficulty,
        stakelock::StakePoolData,
    },
    primitives::{Amount, BlockHeight, H256, Idable, per_thousand::PerThousand},
    time_getter::{MonotonicTimeGetter, TimeGetter},
};
use consensus::{
    GenerateBlockInputData, PoSGenerateBlockInputData, calculate_effective_pool_balance,
    compact_target_to_target,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use mempool::{MempoolConfig, MempoolHandle, MempoolInit};
use p2p::{
    P2pHandle, peer_manager::peerdb::storage_impl::PeerDbStorageImpl, test_helpers::test_p2p_config,
};
use randomness::{CryptoRng, Rng, RngExt as _};
use storage_inmemory::InMemory;
use subsystem::Manager;

use crate::{
    config::BlockProdConfig, detail::BlockProduction, prepare_thread_pool, test_blockprod_config,
};

/// A collection of objects needed to run a blockprod test.
///
/// Note that the subsystem manager is not a part of it; this is because in most tests
/// the test setup object will be moved into a separate tokio task where BlockProduction
/// will be created and tested, while the manager object has to remain outside the task.
pub struct BlockprodTestSetup {
    pub chain_config: Arc<ChainConfig>,
    pub time_getter: TimeGetter,
    pub chainstate: ChainstateHandle,
    pub mempool: MempoolHandle,
    pub p2p: P2pHandle,
}

impl BlockprodTestSetup {
    pub async fn assert_process_block(&self, new_block: Block) -> BlockIndex {
        assert_process_block(&self.chainstate, &self.mempool, new_block).await
    }

    pub fn make_blockprod_builder(&self) -> TestBlockProdBuilder<'_> {
        TestBlockProdBuilder {
            test_setup: self,
            blockprod_config: None,
            chainstate: None,
            mempool: None,
        }
    }
}

/// A builder that produces `BlockprodTestSetup` and the subsystem manager.
pub struct BlockprodTestSetupBuilder {
    chain_config: Option<Arc<ChainConfig>>,
    time_getter: Option<TimeGetter>,
    mempool_config: Option<MempoolConfig>,
}

impl BlockprodTestSetupBuilder {
    pub fn new() -> Self {
        Self {
            chain_config: None,
            time_getter: None,
            mempool_config: None,
        }
    }

    pub fn with_chain_config(mut self, chain_config: Arc<ChainConfig>) -> Self {
        self.chain_config = Some(chain_config);
        self
    }

    pub fn with_time_getter(mut self, time_getter: TimeGetter) -> Self {
        self.time_getter = Some(time_getter);
        self
    }

    pub fn with_mempool_config(mut self, mempool_config: MempoolConfig) -> Self {
        self.mempool_config = Some(mempool_config);
        self
    }

    pub fn build(self) -> (BlockprodTestSetup, Manager) {
        let chain_config = self.chain_config.unwrap_or_else(|| Arc::new(create_unit_test_config()));
        let time_getter = self.time_getter.unwrap_or_default();

        let manager_config =
            subsystem::ManagerConfig::new("blockprod-unit-test").enable_signal_handlers();
        let mut manager = Manager::new_with_config(manager_config);

        let chainstate_config = ChainstateConfig {
            max_tip_age: Duration::from_secs(60 * 60 * 24 * 365 * 100).into(),
            // There is at least one long test in blockprod that gets significantly slowed down
            // by the heavy checks in chainstate. But since the checks are not very useful in blockprod
            // tests in general, we disable them globally.
            enable_heavy_checks: Some(false),

            max_db_commit_attempts: Default::default(),
            enable_db_reckless_mode_in_ibd: Default::default(),
            max_orphan_blocks: Default::default(),
            allow_checkpoints_mismatch: Default::default(),
        };

        let mempool_config = self.mempool_config.unwrap_or_else(MempoolConfig::new);

        let chainstate = chainstate::make_chainstate(
            Arc::clone(&chain_config),
            chainstate_config,
            Store::new_empty().unwrap(),
            DefaultTransactionVerificationStrategy::new(),
            None,
            time_getter.clone(),
            None,
        )
        .unwrap();

        let chainstate = manager.add_subsystem("chainstate", chainstate);

        let mempool_init = MempoolInit::new(
            Arc::clone(&chain_config),
            mempool_config,
            subsystem::Handle::clone(&chainstate),
            time_getter.clone(),
        )
        .unwrap();
        let mempool = manager.add_custom_subsystem("mempool", |hdl, _| mempool_init.init(hdl));

        let mut p2p_config = test_p2p_config();
        p2p_config.bind_addresses = vec![SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into()];

        let p2p = p2p::make_p2p(
            true,
            Arc::clone(&chain_config),
            Arc::new(p2p_config),
            subsystem::Handle::clone(&chainstate),
            mempool.clone(),
            time_getter.clone(),
            MonotonicTimeGetter::default(),
            PeerDbStorageImpl::new(InMemory::new()).unwrap(),
        )
        .unwrap()
        .add_to_manager("p2p", &mut manager);

        (
            BlockprodTestSetup {
                chain_config,
                time_getter,
                chainstate,
                mempool,
                p2p,
            },
            manager,
        )
    }
}

/// A builder that produces `BlockProduction` from `BlockprodTestSetup` with some optional overrides.
pub struct TestBlockProdBuilder<'a> {
    test_setup: &'a BlockprodTestSetup,
    blockprod_config: Option<BlockProdConfig>,
    chainstate: Option<ChainstateHandle>,
    mempool: Option<MempoolHandle>,
}

impl<'a> TestBlockProdBuilder<'a> {
    pub fn with_blockprod_config(mut self, blockprod_config: BlockProdConfig) -> Self {
        self.blockprod_config = Some(blockprod_config);
        self
    }

    pub fn with_chainstate(mut self, chainstate: ChainstateHandle) -> Self {
        self.chainstate = Some(chainstate);
        self
    }

    pub fn with_mempool(mut self, mempool: MempoolHandle) -> Self {
        self.mempool = Some(mempool);
        self
    }

    pub fn build(self) -> BlockProduction {
        let blockprod_config = self.blockprod_config.unwrap_or_else(test_blockprod_config);
        let chainstate = self.chainstate.unwrap_or_else(|| self.test_setup.chainstate.clone());
        let mempool = self.mempool.unwrap_or_else(|| self.test_setup.mempool.clone());

        BlockProduction::new(
            Arc::clone(&self.test_setup.chain_config),
            Arc::new(blockprod_config),
            chainstate,
            mempool,
            self.test_setup.p2p.clone(),
            self.test_setup.time_getter.clone(),
            prepare_thread_pool(1),
        )
        .unwrap()
    }
}

/// A bunch of data specific to PoS tests.
pub struct PoSTestSetup {
    pub chain_config: Arc<ChainConfig>,
    pub genesis_stake_private_key: PrivateKey,
    pub genesis_vrf_private_key: VRFPrivateKey,
    pub create_genesis_pool_utxo: TxOutput,
}

impl PoSTestSetup {
    pub fn make_first_pos_block_input_data(&self) -> GenerateBlockInputData {
        GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
            self.genesis_stake_private_key.clone(),
            self.genesis_vrf_private_key.clone(),
            PoolId::new(H256::zero()),
            vec![TxInput::from_utxo(
                OutPointSourceId::BlockReward(self.chain_config.genesis_block_id()),
                0,
            )],
            vec![self.create_genesis_pool_utxo.clone()],
        )))
    }
}

/// A builder that produces `PoSTestSetup`.
pub struct PoSTestSetupBuilder {
    chain_config_builder: Option<chain::config::Builder>,
    extra_genesis_txos: Vec<TxOutput>,
    pos_switch_height: BlockHeight,
}

impl PoSTestSetupBuilder {
    pub fn new() -> Self {
        Self {
            chain_config_builder: None,
            extra_genesis_txos: Vec::new(),
            pos_switch_height: BlockHeight::new(1),
        }
    }

    pub fn with_chain_config_builder(
        mut self,
        chain_config_builder: chain::config::Builder,
    ) -> Self {
        self.chain_config_builder = Some(chain_config_builder);
        self
    }

    pub fn with_extra_genesis_txos(mut self, extra_genesis_txos: Vec<TxOutput>) -> Self {
        self.extra_genesis_txos = extra_genesis_txos;
        self
    }

    pub fn with_pos_switch_height(mut self, pos_switch_height: BlockHeight) -> Self {
        self.pos_switch_height = pos_switch_height;
        self
    }

    pub fn build(
        self,
        genesis_timestamp: BlockTimestamp,
        rng: &mut impl CryptoRng,
    ) -> PoSTestSetup {
        let initial_target = pos_initial_difficulty(ChainType::Regtest);

        let (genesis, genesis_stake_private_key, genesis_vrf_private_key, create_genesis_pool_utxo) =
            create_genesis_for_pos_tests(genesis_timestamp, &self.extra_genesis_txos, rng);

        let net_upgrades = NetUpgrades::initialize(vec![
            (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
            (
                self.pos_switch_height,
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(initial_target.into()),
                    config: PoSChainConfigBuilder::new_for_unit_test().build(),
                },
            ),
        ])
        .unwrap();

        let chain_config_builder = self
            .chain_config_builder
            .unwrap_or_else(make_chain_config_builder)
            .genesis_custom(genesis)
            .consensus_upgrades(net_upgrades);
        let chain_config = Arc::new(build_chain_config_for_pos(chain_config_builder));

        PoSTestSetup {
            chain_config,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_utxo,
        }
    }
}

pub async fn assert_process_block(
    chainstate: &ChainstateHandle,
    mempool: &MempoolHandle,
    new_block: Block,
) -> BlockIndex {
    let block_id = new_block.get_id();

    // Subscribe to mempool events, so that we can wait for it to become up-to-date with
    // the new block.
    // Note that currently we don't have a mechanism to remove a subscription, so "dead" event
    // handlers will accumulate each time this function is called. But it's not a big deal in tests.
    let (tip_sx, tip_rx) = tokio::sync::oneshot::channel();
    let tip_sx = utils::sync::Mutex::new(Some(tip_sx));
    mempool
        .call_mut(move |m| {
            m.subscribe_to_subsystem_events(Arc::new({
                move |evt| match evt {
                    mempool::event::MempoolEvent::NewTip(tip) => {
                        if let Some(tip_sx) = tip_sx.lock().unwrap().take() {
                            assert_eq!(tip.block_id(), &block_id);
                            let _ = tip_sx.send(());
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
            let new_block_index =
                this.process_block(new_block.clone(), BlockSource::Local).unwrap().unwrap();

            assert_eq!(
                new_block.header().header().block_id(),
                *new_block_index.block_id(),
                "The new block's id is different from the new block index's block id",
            );

            let best_block_index = this.get_best_block_index().unwrap();

            assert_eq!(
                new_block_index.clone().into_gen_block_index().block_id(),
                best_block_index.block_id(),
                "The new block index is not the best block index"
            );

            new_block_index
        })
        .await
        .unwrap();

    tip_rx.await.unwrap();

    block_index
}

pub fn make_genesis_timestamp(time_getter: &TimeGetter, rng: &mut impl Rng) -> BlockTimestamp {
    BlockTimestamp::from_int_seconds(
        (time_getter.get_time()
            - Duration::new(
                // Genesis must be in the past: now - (1 day..2 weeks)
                rng.random_range(60 * 60 * 24..60 * 60 * 24 * 14),
                0,
            ))
        .unwrap()
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
    extra_txos: &[TxOutput],
    rng: &mut impl CryptoRng,
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
                PerThousand::new(1000).unwrap(),
                Amount::ZERO,
            )),
        )
    };

    let mut txos = vec![create_pool_txoutput.clone()];
    txos.extend_from_slice(extra_txos);

    let genesis = Genesis::new("blockprod-testing".into(), timestamp, txos);

    (
        genesis,
        stake_private_key,
        vrf_private_key,
        create_pool_txoutput,
    )
}

pub fn make_chain_config_builder() -> chain::config::Builder {
    chain::config::Builder::new(ChainType::Regtest)
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

pub async fn add_local_txs_to_mempool(mempool: &MempoolHandle, txs: Vec<SignedTransaction>) {
    mempool
        .call_mut(move |mp| {
            let origin = mempool::tx_origin::LocalTxOrigin::Mempool;
            let options = mempool::TxOptions::default_for(origin.into());

            for tx in txs {
                mp.add_transaction_local(tx, origin, options.clone()).unwrap();
            }
        })
        .await
        .unwrap()
}
