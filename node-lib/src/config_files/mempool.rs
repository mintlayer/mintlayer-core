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
use mempool::MempoolConfig;

use crate::RunOptions;

/// Mempool configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MempoolConfigFile {
    /// Minimum transaction relay fee per byte.
    pub min_tx_relay_fee_per_byte: Option<u64>,
}

impl MempoolConfigFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_run_options(config: MempoolConfigFile, options: &RunOptions) -> MempoolConfigFile {
        let MempoolConfigFile {
            min_tx_relay_fee_per_byte,
        } = config;

        let min_tx_relay_fee_per_byte =
            min_tx_relay_fee_per_byte.or(options.min_tx_relay_fee_per_byte);

        MempoolConfigFile {
            min_tx_relay_fee_per_byte,
        }
    }
}

impl From<MempoolConfigFile> for MempoolConfig {
    fn from(config_file: MempoolConfigFile) -> Self {
        let MempoolConfigFile {
            min_tx_relay_fee_per_byte,
        } = config_file;

        Self {
            min_tx_relay_fee_per_byte: min_tx_relay_fee_per_byte
                .map(|val| Amount::from_atoms(val.into()))
                .into(),
        }
    }
}
