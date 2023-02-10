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

use super::chainstate::ChainstateConfigFile;

/// Storage type to use
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub enum StorageBackendConfigFile {
    #[serde(rename = "lmdb")]
    #[default]
    Lmdb,
    #[serde(rename = "inmemory", alias = "in-memory")]
    InMemory,
}

impl From<StorageBackendConfigFile> for StorageBackendConfig {
    fn from(c: StorageBackendConfigFile) -> Self {
        match c {
            StorageBackendConfigFile::Lmdb => StorageBackendConfig::Lmdb,
            StorageBackendConfigFile::InMemory => StorageBackendConfig::InMemory,
        }
    }
}

impl std::str::FromStr for StorageBackendConfigFile {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de = serde::de::value::StrDeserializer::new(s);
        Deserialize::deserialize(de)
    }
}

/// Storage configuration
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ChainstateLauncherConfigFile {
    /// Storage backend to use
    #[serde(default)]
    pub storage_backend: StorageBackendConfigFile,

    /// Chainstate configuration
    #[serde(flatten)]
    pub chainstate_config: ChainstateConfigFile,
}

impl ChainstateLauncherConfigFile {
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<ChainstateLauncherConfigFile> for ChainstateLauncherConfig {
    fn from(c: ChainstateLauncherConfigFile) -> Self {
        ChainstateLauncherConfig {
            storage_backend: c.storage_backend.into(),
            chainstate_config: c.chainstate_config.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn backend_from_str() {
        assert_eq!("lmdb".parse(), Ok(StorageBackendConfigFile::Lmdb));
        assert_eq!("in-memory".parse(), Ok(StorageBackendConfigFile::InMemory));
        assert_eq!("inmemory".parse(), Ok(StorageBackendConfigFile::InMemory));
        assert!("meh".parse::<StorageBackendConfigFile>().is_err());
        assert!("".parse::<StorageBackendConfigFile>().is_err());
    }
}
