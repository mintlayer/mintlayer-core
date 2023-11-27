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
}

impl MempoolConfigFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_run_options(config: MempoolConfigFile, options: &RunOptions) -> MempoolConfigFile {
        let MempoolConfigFile {
            min_tx_relay_fee_rate,
        } = config;

        let min_tx_relay_fee_rate = min_tx_relay_fee_rate.or(options.min_tx_relay_fee_rate);

        MempoolConfigFile {
            min_tx_relay_fee_rate,
        }
    }
}

impl From<MempoolConfigFile> for MempoolConfig {
    fn from(config_file: MempoolConfigFile) -> Self {
        let MempoolConfigFile {
            min_tx_relay_fee_rate,
        } = config_file;

        Self {
            min_tx_relay_fee_rate: min_tx_relay_fee_rate
                .map(|val| FeeRate::from_amount_per_kb(Amount::from_atoms(val.into())))
                .into(),
        }
    }
}
