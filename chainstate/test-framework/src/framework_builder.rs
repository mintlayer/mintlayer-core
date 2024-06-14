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

use crate::{
    key_manager::KeyManager,
    staking_pools::{StakingPoolsForAllHeights, StakingPoolsForOneHeight},
    tx_verification_strategy::{
        DisposableTransactionVerificationStrategy, RandomizedTransactionVerificationStrategy,
    },
    TestFramework, TestStore,
};
use chainstate::{BlockError, ChainstateConfig, DefaultTransactionVerificationStrategy};
use common::{
    chain::{ChainConfig, PoolId, UtxoOutPoint},
    time_getter::TimeGetter,
};
use crypto::{key::PrivateKey, vrf::VRFPrivateKey};
use randomness::{CryptoRng, Rng};
use test_utils::{mock_time_getter::mocked_time_getter_seconds, random::Seed};
use utils::atomics::SeqCstAtomicU64;
use variant_count::VariantCount;

#[derive(VariantCount)]
pub enum TxVerificationStrategy {
    Default,
    Disposable,
    Randomized(Seed),
}

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;
/// The TestFramework builder.
pub struct TestFrameworkBuilder {
    chain_config: ChainConfig,
    chainstate_config: ChainstateConfig,
    chainstate_storage: TestStore,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    time_getter: Option<TimeGetter>,
    time_value: Option<Arc<SeqCstAtomicU64>>,
    tx_verification_strategy: TxVerificationStrategy,
    initial_time_since_genesis: u64,
    // Note: these two are mutually exclusive
    staking_pools: Option<StakingPoolsForAllHeights>,
    staking_pools_at_genesis: Option<BTreeMap<PoolId, (PrivateKey, VRFPrivateKey, UtxoOutPoint)>>,
}

impl TestFrameworkBuilder {
    /// Constructs a builder instance with values appropriate for most of the tests.
    pub fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let chain_config = common::chain::config::create_unit_test_config();
        let chainstate_config = ChainstateConfig::new();
        let chainstate_storage = TestStore::new_empty().unwrap();
        let time_getter = None;
        let time_value = None;
        let initial_time_since_genesis = 0;

        assert_eq!(TxVerificationStrategy::VARIANT_COUNT, 3);
        let tx_verification_strategy = match rng.gen_range(0..3) {
            0 => TxVerificationStrategy::Default,
            1 => TxVerificationStrategy::Disposable,
            2 => TxVerificationStrategy::Randomized(Seed::from_u64(rng.next_u64())),
            _ => unreachable!(),
        };

        TestFrameworkBuilder {
            chain_config,
            chainstate_config,
            chainstate_storage,
            custom_orphan_error_hook: None,
            time_getter,
            time_value,
            tx_verification_strategy,
            initial_time_since_genesis,
            staking_pools: None,
            staking_pools_at_genesis: None,
        }
    }

    pub fn from_existing_framework(tf: TestFramework) -> Self {
        let chain_config = (**tf.chainstate.get_chain_config()).clone();
        let chainstate_config = tf.chainstate.get_chainstate_config();
        let chainstate_storage = tf.storage;
        let time_getter = Some(tf.time_getter);
        let time_value = tf.time_value;
        // TODO: get strategy from `tf`
        let tx_verification_strategy = TxVerificationStrategy::Default;
        let initial_time_since_genesis = 0;

        TestFrameworkBuilder {
            chain_config,
            chainstate_config,
            chainstate_storage,
            custom_orphan_error_hook: None,
            time_getter,
            time_value,
            tx_verification_strategy,
            initial_time_since_genesis,
            staking_pools_at_genesis: None,
            staking_pools: Some(tf.staking_pools),
        }
    }

    pub fn with_storage(mut self, s: TestStore) -> Self {
        self.chainstate_storage = s;
        self
    }

    pub fn with_chain_config(mut self, chain_config: ChainConfig) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_chainstate_config(mut self, config: ChainstateConfig) -> Self {
        self.chainstate_config = config;
        self
    }

    /// Set max tip age in [ChainstateConfig] to given value.
    pub fn with_max_tip_age(mut self, max_tip_age: chainstate::MaxTipAge) -> Self {
        self.chainstate_config.max_tip_age = max_tip_age;
        self
    }

    pub fn with_orphan_error_hook(mut self, hook: Arc<OrphanErrorHandler>) -> Self {
        self.custom_orphan_error_hook = Some(hook);
        self
    }

    pub fn with_time_getter(mut self, time_getter: TimeGetter) -> Self {
        self.time_getter = Some(time_getter);
        self.time_value = None;
        self
    }

    pub fn with_time_value(mut self, time_value: Arc<SeqCstAtomicU64>) -> Self {
        self.time_getter = None;
        self.time_value = Some(time_value);
        self
    }

    pub fn with_tx_verification_strategy(mut self, strategy: TxVerificationStrategy) -> Self {
        self.tx_verification_strategy = strategy;
        self
    }

    /// Set initial mock time to given number of seconds after the genesis timestamp.
    pub fn with_initial_time_since_genesis(mut self, initial_time_since_genesis: u64) -> Self {
        self.initial_time_since_genesis = initial_time_since_genesis;
        self
    }

    pub fn with_staking_pools_at_genesis(
        mut self,
        staking_pools: BTreeMap<PoolId, (PrivateKey, VRFPrivateKey, UtxoOutPoint)>,
    ) -> Self {
        self.staking_pools_at_genesis = Some(staking_pools);
        self
    }

    /// If self.time_getter and self.time_value both exist, which means that they were obtained
    /// from an already constructed TestFramework, just return them.
    /// Otherwise, create the TimeGetter of the TestFramework, with the following logic:
    /// The default TimeGetter of the TestFramework simply loads the value of time from an atomic u64
    /// If a custom TimeGetter is supplied, then this value won't exist
    fn create_time_getter_and_value(&self) -> (TimeGetter, Option<Arc<SeqCstAtomicU64>>) {
        if self.time_getter.is_some() && self.time_value.is_some() {
            return (self.time_getter.clone().unwrap(), self.time_value.clone());
        }

        let time_value = Arc::new(SeqCstAtomicU64::new(
            self.chain_config.genesis_block().timestamp().as_int_seconds(),
        ));
        time_value.fetch_add(self.initial_time_since_genesis);

        let default_time_getter = mocked_time_getter_seconds(Arc::clone(&time_value));

        let time_getter = self.time_getter.clone().unwrap_or(default_time_getter);

        let time_value = match self.time_getter {
            Some(_) => None,          // a custom time getter supplied
            None => Some(time_value), // default time getter
        };

        (time_getter, time_value)
    }

    pub fn try_build(self) -> Result<TestFramework, chainstate::ChainstateError> {
        let (time_getter, time_value) = self.create_time_getter_and_value();

        let chain_config = Arc::new(self.chain_config);
        let chainstate = match self.tx_verification_strategy {
            TxVerificationStrategy::Default => chainstate::make_chainstate(
                Arc::clone(&chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                DefaultTransactionVerificationStrategy::new(),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
            TxVerificationStrategy::Disposable => chainstate::make_chainstate(
                Arc::clone(&chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                DisposableTransactionVerificationStrategy::new(),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
            TxVerificationStrategy::Randomized(seed) => chainstate::make_chainstate(
                Arc::clone(&chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                RandomizedTransactionVerificationStrategy::new(seed),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
        }?;

        assert!(self.staking_pools.is_none() || self.staking_pools_at_genesis.is_none());

        let staking_pools = if let Some(staking_pools) = self.staking_pools {
            staking_pools
        } else if let Some(staking_pools_at_genesis) = self.staking_pools_at_genesis {
            let genesis_id = chain_config.genesis_block_id();
            StakingPoolsForAllHeights::from_data(BTreeMap::from([(
                genesis_id,
                StakingPoolsForOneHeight::from_data(
                    staking_pools_at_genesis
                        .into_iter()
                        .map(
                            |(pool_id, (staker_sk, staker_vrf_sk, kernel_input_outpoint))| {
                                (
                                    pool_id,
                                    (staker_sk, staker_vrf_sk, kernel_input_outpoint, genesis_id),
                                )
                            },
                        )
                        .collect::<BTreeMap<_, _>>(),
                ),
            )]))
        } else {
            StakingPoolsForAllHeights::new()
        };

        let key_manager = KeyManager::new(
            staking_pools
                .all_staking_pools()
                .values()
                .flat_map(|pools| pools.staking_pools().values())
                .map(|(pk, _, _, _)| pk),
        );

        Ok(TestFramework {
            chainstate,
            storage: self.chainstate_storage,
            block_indexes: Vec::new(),
            time_getter,
            time_value,
            staking_pools,
            key_manager,
        })
    }

    pub fn build(self) -> TestFramework {
        self.try_build().unwrap()
    }
}
