// Copyright (c) 2021-2022 RBB S.r.l
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

//! Chainstate launcher configuration

use chainstate::ChainstateConfig;

/// Storage type to use
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendConfig {
    Lmdb,
    InMemory,
}

impl Default for StorageBackendConfig {
    fn default() -> Self {
        Self::Lmdb
    }
}

/// Storage configuration
#[must_use]
#[derive(Debug, Default)]
pub struct ChainstateLauncherConfig {
    /// Storage backend to use
    pub storage_backend: StorageBackendConfig,

    /// Chainstate configuration
    pub chainstate_config: ChainstateConfig,
}

impl ChainstateLauncherConfig {
    pub fn new() -> Self {
        Self::default()
    }
}
