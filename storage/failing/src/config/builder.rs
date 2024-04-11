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

use std::collections::BTreeMap;

use storage::schema;
use storage_core::DbMapId;

use crate::config::{ErrorGeneration, ErrorSet, FailureConfig};

/// Builder for failure configuration.
///
/// While this is parametrized by the schema to automate the lookup of db indices, catch out of
/// bounds errors and check database map existence, it does not guarantee the schema is the same as
/// what is used during the storage initialization. Create an abstraction for creating the database
/// on top of this if that guarantee is desired.
pub struct Builder<Sch> {
    config: FailureConfig,
    _phantom: std::marker::PhantomData<Sch>,
}

impl<Sch> Builder<Sch> {
    pub fn new(config: FailureConfig) -> Self {
        let _phantom = std::marker::PhantomData;
        Self { config, _phantom }
    }

    /// Build the configuration
    pub fn build(self) -> FailureConfig {
        self.config
    }

    /// Configure max number of spurious failures in a single transaction.
    ///
    /// Used to avoid exceeding max number of attempts certain operation is configured to perform.
    pub fn max_failures_per_transaction(mut self, max: u32) -> Self {
        self.config.max_failures_per_transaction = max;
        self
    }

    /// Max number of spurious failures during the whole storage lifetime.
    pub fn max_failures_total(mut self, max: u32) -> Self {
        self.config.max_failures_total = max;
        self
    }

    /// Default spurious failure rate for write operations.
    pub fn background_write_errors(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self {
        self.config.default_error_generation_write = ErrorGeneration::new(probability, errs);
        self
    }

    /// Default spurious failure rate for delete operations.
    pub fn background_del_errors(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self {
        self.config.default_error_generation_del = ErrorGeneration::new(probability, errs);
        self
    }

    /// Spurious failure rate on transaction commit.
    pub fn commit_errors(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self {
        self.config.error_generation_commit = ErrorGeneration::new(probability, errs);
        self
    }

    /// Spurious failure rate when starting a new read-write transaction.
    pub fn start_rw_tx_errors(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self {
        self.config.error_generation_start_rw_tx = ErrorGeneration::new(probability, errs);
        self
    }

    /// Spurious failure rate when writing to given DB map.
    pub fn write_errors<DbMap, I>(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self
    where
        DbMap: schema::DbMap,
        Sch: schema::HasDbMap<DbMap, I>,
    {
        Self::update_op_map(&mut self.config.error_generation_write, probability, errs);
        self
    }

    /// Spurious failure rate when deleting from given DB map.
    pub fn del_errors<DbMap, I>(mut self, probability: f32, errs: impl Into<ErrorSet>) -> Self
    where
        DbMap: schema::DbMap,
        Sch: schema::HasDbMap<DbMap, I>,
    {
        Self::update_op_map(&mut self.config.error_generation_del, probability, errs);
        self
    }

    fn update_op_map<DbMap, I>(
        op_map: &mut BTreeMap<DbMapId, ErrorGeneration>,
        probability: f32,
        errs: impl Into<ErrorSet>,
    ) where
        DbMap: schema::DbMap,
        Sch: schema::HasDbMap<DbMap, I>,
    {
        let map_id = <Sch as schema::HasDbMap<DbMap, I>>::INDEX;
        let eg = ErrorGeneration::new(probability, errs);
        let _old = op_map.insert(map_id, eg);
    }
}

impl<Sch> Clone for Builder<Sch> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Sch> std::fmt::Debug for Builder<Sch> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { config, _phantom } = self;
        config.fmt(f)
    }
}
