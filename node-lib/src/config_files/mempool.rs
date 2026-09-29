// Copyright (c) 2021-2023 RBB S.r.l
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

use common::primitives::Amount;
use mempool::{FeeRate, MempoolConfig};

use crate::RunOptions;

/// Mempool configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct MempoolConfigFile {
    /// Minimum transaction relay fee rate (in atoms per 1000 bytes).
    pub min_tx_relay_fee_rate: Option<u64>,

    /// Maximum number of transactions that a single cluster can contain.
    pub max_cluster_tx_count: Option<usize>,

    /// Maximum total size of transactions that is allowed in a single cluster.
    pub max_cluster_size_bytes: Option<usize>,

    /// Whether to park local-origin transactions with unknown inputs in the orphan pool.
    pub allow_local_orphans: Option<bool>,
}

impl MempoolConfigFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_run_options(config: MempoolConfigFile, options: &RunOptions) -> MempoolConfigFile {
        let MempoolConfigFile {
            min_tx_relay_fee_rate,
            max_cluster_tx_count,
            max_cluster_size_bytes,
            allow_local_orphans,
        } = config;

        let min_tx_relay_fee_rate = min_tx_relay_fee_rate.or(options.min_tx_relay_fee_rate);
        let max_cluster_tx_count =
            max_cluster_tx_count.or(options.mempool_max_cluster_transaction_count);
        let max_cluster_size_bytes =
            max_cluster_size_bytes.or(options.mempool_max_cluster_size_bytes);
        // Note: `allow_local_orphans` is intentionally not exposed as a CLI option; it can only
        // be set through the mempool config file.

        MempoolConfigFile {
            min_tx_relay_fee_rate,
            max_cluster_tx_count,
            max_cluster_size_bytes,
            allow_local_orphans,
        }
    }
}

impl From<MempoolConfigFile> for MempoolConfig {
    fn from(config_file: MempoolConfigFile) -> Self {
        let MempoolConfigFile {
            min_tx_relay_fee_rate,
            max_cluster_tx_count,
            max_cluster_size_bytes,
            allow_local_orphans,
        } = config_file;

        Self {
            min_tx_relay_fee_rate: min_tx_relay_fee_rate
                .map(|val| FeeRate::from_amount_per_kb(Amount::from_atoms(val.into())))
                .into(),
            max_cluster_tx_count: max_cluster_tx_count.into(),
            max_cluster_size_bytes: max_cluster_size_bytes.into(),
            allow_local_orphans: allow_local_orphans.into(),
        }
    }
}
