// Copyright (c) 2024 RBB S.r.l
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

use storage_failing::{Failing, FailureConfig};
use storage_inmemory::InMemory;
use test_utils::random::Seed;

pub use storage_failing::StorageError;

pub type TestStore = chainstate_storage::Store<Failing<InMemory>>;
pub type ConfigBuilder = storage_failing::Builder<chainstate_storage::schema::Schema>;

/// A builder for chainstate testing storage
#[derive(Clone)]
pub struct Builder {
    inner: InMemory,
    config: ConfigBuilder,
}

impl Builder {
    /// Build reliable storage
    pub fn reliable() -> Self {
        let inner = InMemory::default();
        let config = ConfigBuilder::new(FailureConfig::reliable());
        Self { inner, config }
    }

    /// New failing [TestStore] builder.
    pub fn new(config_fn: impl FnOnce(ConfigBuilder) -> ConfigBuilder) -> Self {
        let inner = InMemory::default();
        let config = config_fn(FailureConfig::builder());
        Self { inner, config }
    }

    /// Build the storage.
    pub fn build(self, seed: Seed) -> TestStore {
        let Self { inner, config } = self;
        let backend = Failing::new(inner, config.build(), seed);
        TestStore::from_backend(backend).expect("backend creation to succeed")
    }

    /// Use the specified in-memory backend as the underlying storage.
    pub fn with_inner(mut self, inner: InMemory) -> Self {
        self.inner = inner;
        self
    }

    /// Apply given function to the failure config builder.
    pub fn failure_config(self, config_fn: impl FnOnce(ConfigBuilder) -> ConfigBuilder) -> Self {
        let Self { inner, config } = self;
        Self {
            inner,
            config: config_fn(config),
        }
    }
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { inner: _, config } = self;
        config.fmt(f)
    }
}
