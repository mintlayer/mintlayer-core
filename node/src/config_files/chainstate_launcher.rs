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

use chainstate_launcher::{ChainstateLauncherConfig, StorageBackendConfig};
use serde::{Deserialize, Serialize};

use super::chainstate::ChainstateFileConfig;

/// Storage type to use
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendFileConfig {
    #[serde(rename = "lmdb")]
    Lmdb,
    #[serde(rename = "inmemory", alias = "in-memory")]
    InMemory,
}

impl StorageBackendFileConfig {
    pub fn into_storage_backend_config(self) -> StorageBackendConfig {
        match self {
            StorageBackendFileConfig::Lmdb => StorageBackendConfig::Lmdb,
            StorageBackendFileConfig::InMemory => StorageBackendConfig::InMemory,
        }
    }
}

impl std::str::FromStr for StorageBackendFileConfig {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de = serde::de::value::StrDeserializer::new(s);
        serde::Deserialize::deserialize(de)
    }
}

impl Default for StorageBackendFileConfig {
    fn default() -> Self {
        Self::Lmdb
    }
}

/// Storage configuration
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ChainstateLauncherConfigFile {
    /// Storage backend to use
    #[serde(default)]
    pub storage_backend: StorageBackendFileConfig,

    /// Chainstate configuration
    #[serde(flatten)]
    pub chainstate_config: ChainstateFileConfig,
}

impl ChainstateLauncherConfigFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_chainstate_launcher_config(self) -> ChainstateLauncherConfig {
        ChainstateLauncherConfig {
            storage_backend: self.storage_backend.into_storage_backend_config(),
            chainstate_config: self.chainstate_config.into_chainstate_config(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn backend_from_str() {
        assert_eq!("lmdb".parse(), Ok(StorageBackendFileConfig::Lmdb));
        assert_eq!("in-memory".parse(), Ok(StorageBackendFileConfig::InMemory));
        assert_eq!("inmemory".parse(), Ok(StorageBackendFileConfig::InMemory));
        assert!("meh".parse::<StorageBackendFileConfig>().is_err());
        assert!("".parse::<StorageBackendFileConfig>().is_err());
    }
}
