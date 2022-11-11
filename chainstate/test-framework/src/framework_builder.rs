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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use chainstate::{BlockError, ChainstateConfig, DefaultTransactionVerificationStrategy};
use common::{
    chain::{
        config::{Builder as ChainConfigBuilder, ChainType},
        ChainConfig, Destination, NetUpgrades,
    },
    time_getter::{TimeGetter, TimeGetterFn},
};
use crypto::random::{CryptoRng, Rng};
use test_utils::random::Seed;

use crate::{
    tx_verification_strategy::{
        DisposableTransactionVerificationStrategy, RandomizedTransactionVerificationStrategy,
    },
    TestFramework, TestStore,
};

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
    tx_verification_strategy: TxVerificationStrategy,
}

impl TestFrameworkBuilder {
    /// Constructs a builder instance with values appropriate for most of the tests.
    pub fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = chainstate::ChainstateConfig {
            max_db_commit_attempts: Default::default(),
            max_orphan_blocks: Default::default(),
            min_max_bootstrap_import_buffer_sizes: Default::default(),
            tx_index_enabled: rng.gen::<bool>().into(),
        };
        let chainstate_storage = TestStore::new_empty().unwrap();
        let time_getter = None;
        let tx_verification_strategy = TxVerificationStrategy::Default;

        TestFrameworkBuilder {
            chain_config,
            chainstate_config,
            chainstate_storage,
            custom_orphan_error_hook: None,
            time_getter,
            tx_verification_strategy,
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

    pub fn with_orphan_error_hook(mut self, hook: Arc<OrphanErrorHandler>) -> Self {
        self.custom_orphan_error_hook = Some(hook);
        self
    }

    pub fn with_time_getter(mut self, time_getter: TimeGetter) -> Self {
        self.time_getter = Some(time_getter);
        self
    }

    pub fn with_tx_verification_strategy(mut self, strategy: TxVerificationStrategy) -> Self {
        self.tx_verification_strategy = strategy;
        self
    }

    /// Create the TimeGetter of the TestFramework, with the following logic:
    /// The default TimeGetter of the TestFramework simply loads the value of time from an atomic u64
    /// If a custom TimeGetter is supplied, then this value won't exist
    fn create_time_getter_and_value(&self) -> (TimeGetter, Option<Arc<AtomicU64>>) {
        let time_value = Arc::new(AtomicU64::new(
            self.chain_config.genesis_block().timestamp().as_int_seconds(),
        ));

        let default_time_getter = {
            let current_time = Arc::clone(&time_value);
            let default_time_getter_fn: Arc<TimeGetterFn> =
                Arc::new(move || Duration::from_secs(current_time.load(Ordering::SeqCst)));
            TimeGetter::new(default_time_getter_fn)
        };

        let time_getter = self.time_getter.clone().unwrap_or(default_time_getter);

        let time_value = match self.time_getter {
            Some(_) => None,          // a custom time getter supplied
            None => Some(time_value), // default time getter
        };

        (time_getter, time_value)
    }

    pub fn try_build(self) -> Result<TestFramework, chainstate::ChainstateError> {
        let (time_getter, time_value) = self.create_time_getter_and_value();

        let chainstate = match self.tx_verification_strategy {
            TxVerificationStrategy::Default => chainstate::make_chainstate(
                Arc::new(self.chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                DefaultTransactionVerificationStrategy::new(),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
            TxVerificationStrategy::Disposable => chainstate::make_chainstate(
                Arc::new(self.chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                DisposableTransactionVerificationStrategy::new(),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
            TxVerificationStrategy::Randomized(seed) => chainstate::make_chainstate(
                Arc::new(self.chain_config),
                self.chainstate_config,
                self.chainstate_storage.clone(),
                RandomizedTransactionVerificationStrategy::new(seed),
                self.custom_orphan_error_hook,
                time_getter.clone(),
            ),
        }?;

        Ok(TestFramework {
            chainstate,
            storage: self.chainstate_storage,
            block_indexes: Vec::new(),
            time_getter,
            time_value,
        })
    }

    pub fn build(self) -> TestFramework {
        self.try_build().unwrap()
    }
}
