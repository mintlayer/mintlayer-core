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

use serde::{Deserialize, Serialize};

/// Storage type to use
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    #[serde(rename = "lmdb")]
    Lmdb,
    #[serde(rename = "inmemory", alias = "in-memory")]
    InMemory,
}

impl std::str::FromStr for StorageBackend {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de = serde::de::value::StrDeserializer::new(s);
        serde::Deserialize::deserialize(de)
    }
}

impl Default for StorageBackend {
    fn default() -> Self {
        Self::Lmdb
    }
}

/// Storage configuration
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ChainstateLauncherConfig {
    /// Storage backend to use
    #[serde(default)]
    pub storage_backend: StorageBackend,

    /// Chainstate configuration
    #[serde(flatten)]
    pub chainstate_config: ChainstateConfig,
}

impl ChainstateLauncherConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn backend_from_str() {
        assert_eq!("lmdb".parse(), Ok(StorageBackend::Lmdb));
        assert_eq!("in-memory".parse(), Ok(StorageBackend::InMemory));
        assert_eq!("inmemory".parse(), Ok(StorageBackend::InMemory));
        assert!("meh".parse::<StorageBackend>().is_err());
        assert!("".parse::<StorageBackend>().is_err());
    }
}
