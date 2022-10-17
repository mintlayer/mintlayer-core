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

//! Storage configuration

use serde::{Deserialize, Serialize};

/// Storage type to use
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    Lmdb,
    InMemory,
}

impl StorageBackend {
    fn default() -> Self {
        Self::Lmdb
    }
}

impl std::str::FromStr for StorageBackend {
    type Err = StorageBackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lmdb" => Ok(StorageBackend::Lmdb),
            "inmemory" | "in-memory" => Ok(StorageBackend::InMemory),
            name => {
                let name = name.into();
                Err(StorageBackendParseError::Unrecognized { name })
            }
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum StorageBackendParseError {
    #[error("Unrecognized backend '{name}'")]
    Unrecognized { name: String },
}

/// Storage configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct StorageConfig {
    #[serde(default = "StorageBackend::default")]
    pub backend: StorageBackend,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let backend = StorageBackend::default();
        StorageConfig { backend }
    }
}

impl StorageConfig {
    pub fn new() -> Self {
        Self::default()
    }
}
