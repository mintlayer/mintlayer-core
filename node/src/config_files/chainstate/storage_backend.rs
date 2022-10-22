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

use serde::{Deserialize, Serialize};

/// Storage type to use
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendFileConfig {
    #[serde(rename = "lmdb")]
    Lmdb,
    #[serde(rename = "inmemory", alias = "in-memory")]
    InMemory,
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
