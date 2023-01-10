// Copyright (c) 2023 RBB S.r.l
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

//! Transaction index cache with enabled/disabled flag.

use super::{config::TransactionVerifierConfig, tx_index_cache};
use tx_index_cache::TxIndexCache;

/// [`TxIndexCache`] that can be enabled or disabled (using a config).
pub struct OptionalTxIndexCache {
    enabled: bool,
    inner: TxIndexCache,
}

impl OptionalTxIndexCache {
    pub fn new(enabled: bool) -> Self {
        let inner = TxIndexCache::new();
        Self { enabled, inner }
    }

    pub fn from_config(config: &TransactionVerifierConfig) -> Self {
        Self::new(config.tx_index_enabled)
    }

    #[cfg(test)]
    pub fn new_for_test(map: tx_index_cache::TxIndexMap) -> Self {
        let inner = TxIndexCache::new_for_test(map);
        let enabled = true;
        Self { enabled, inner }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn as_ref(&self) -> Option<&TxIndexCache> {
        self.enabled.then_some(&self.inner)
    }

    pub fn as_mut(&mut self) -> Option<&mut TxIndexCache> {
        self.enabled.then_some(&mut self.inner)
    }

    /// Take the inner cache, even if disabled
    pub fn take_always(self) -> TxIndexCache {
        self.inner
    }
}
