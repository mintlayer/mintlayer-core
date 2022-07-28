// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use chainstate_storage::Store;
use common::chain::{
    config::{Builder as ChainConfigBuilder, ChainType},
    ChainConfig, Destination, NetUpgrades,
};

use crate::detail::{
    OrphanErrorHandler,
    {tests::test_framework::TestFramework, Chainstate, ChainstateConfig, TimeGetter},
};

/// The TestFramework builder.
pub struct TestFrameworkBuilder {
    chain_config: ChainConfig,
    chainstate_config: ChainstateConfig,
    chainstate_storage: Store,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    time_getter: TimeGetter,
}

impl TestFrameworkBuilder {
    /// Constructs a builder instance with values appropriate for most of the tests.
    pub fn new() -> Self {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = ChainstateConfig::default();
        let chainstate_storage = Store::new_empty().unwrap();
        let time_getter = TimeGetter::default();

        TestFrameworkBuilder {
            chain_config,
            chainstate_config,
            chainstate_storage,
            custom_orphan_error_hook: None,
            time_getter,
        }
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
        self.time_getter = time_getter;
        self
    }

    pub fn build(self) -> TestFramework {
        let chainstate = Chainstate::new(
            Arc::new(self.chain_config),
            self.chainstate_config,
            self.chainstate_storage,
            self.custom_orphan_error_hook,
            self.time_getter,
        )
        .unwrap();

        TestFramework {
            chainstate,
            block_indexes: Vec::new(),
        }
    }
}
