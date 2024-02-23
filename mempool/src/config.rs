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

use std::{str::FromStr, time::Duration};

use common::primitives::{Amount, BlockDistance};
use rpc::description::HasValueHint;
use utils::make_config_setting;

use crate::FeeRate;

/// Mempool size configuration
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub struct MempoolMaxSize(usize);

impl MempoolMaxSize {
    pub fn from_bytes(n: usize) -> Self {
        Self(n)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }
}

impl Default for MempoolMaxSize {
    fn default() -> Self {
        Self::from_bytes(MAX_MEMPOOL_SIZE_BYTES)
    }
}

impl std::fmt::Display for MempoolMaxSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}B", self.0)
    }
}

impl serde::Serialize for MempoolMaxSize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0 as u64)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum StringOrUint {
    String(String),
    UInt(u64),
}

impl<'de> serde::Deserialize<'de> for MempoolMaxSize {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        match StringOrUint::deserialize(deserializer)? {
            StringOrUint::String(s) => {
                let bytes: byte_unit::Byte = rpc::handle_result(byte_unit::Byte::from_str(&s))
                    .map_err(|e| {
                        D::Error::custom(format!(
                            "Conversion to integer from data size failed: {e}"
                        ))
                    })?;

                let bytes: usize = bytes.as_u64().try_into().map_err(|_| {
                    D::Error::custom(format!("Integer {} is too large to fit", bytes))
                })?;

                let max_size = MempoolMaxSize::from_bytes(bytes);

                Ok(max_size)
            }
            StringOrUint::UInt(bytes) => {
                let bytes: usize = bytes.try_into().map_err(|_| {
                    D::Error::custom(format!("Integer {} is too large to fit", bytes))
                })?;

                let max_size = MempoolMaxSize::from_bytes(bytes);

                Ok(max_size)
            }
        }
    }
}

impl HasValueHint for MempoolMaxSize {
    const HINT_SER: rpc_description::ValueHint =
        rpc_description::ValueHint::Prim("number in bytes");
    const HINT_DE: rpc_description::ValueHint = rpc_description::ValueHint::Prim(
        "String with units, such as MB/KB/GB, or integer for bytes",
    );
}

pub const ENABLE_RBF: bool = false;

// Number of times we try to add transaction if the tip moves during validation
pub const MAX_TX_ADDITION_ATTEMPTS: usize = 3;

pub const ROLLING_FEE_BASE_HALFLIFE: Duration = Duration::new(60 * 60 * 12, 1);

pub const MAX_BIP125_REPLACEMENT_CANDIDATES: usize = 100;

pub const MAX_MEMPOOL_SIZE_BYTES: usize = 300_000_000;

pub const DEFAULT_MEMPOOL_EXPIRY: Duration = Duration::new(336 * 60 * 60, 0);

pub const ROLLING_FEE_DECAY_INTERVAL: Duration = Duration::new(10, 0);

pub const DEFAULT_ORPHAN_POOL_CAPACITY: usize = 100;

pub const DEFAULT_ORPHAN_TX_EXPIRY_INTERVAL: Duration = Duration::from_secs(5 * 10);

pub const MAX_ORPHAN_TX_SIZE: usize = 20_000;

pub const MAX_ORPHAN_ACCOUNT_GAP: u64 = 2;

pub const FUTURE_TIMELOCK_TOLERANCE: Duration = Duration::from_secs(5 * 60);

pub const FUTURE_TIMELOCK_TOLERANCE_BLOCKS: BlockDistance = BlockDistance::new(5);

pub const INCREMENTAL_RELAY_FEE_RATE: FeeRate =
    FeeRate::from_amount_per_kb(Amount::from_atoms(1000));

pub const INCREMENTAL_RELAY_THRESHOLD: FeeRate =
    FeeRate::from_amount_per_kb(Amount::from_atoms(500));

// 10^-3 of a coin per 1000 bytes
make_config_setting!(
    MinTxRelayFeeRate,
    FeeRate,
    FeeRate::from_amount_per_kb(Amount::from_atoms(100_000_000))
);

#[derive(Debug, Clone, Default)]
pub struct MempoolConfig {
    pub min_tx_relay_fee_rate: MinTxRelayFeeRate,
}

impl MempoolConfig {
    pub fn new() -> Self {
        Self::default()
    }
}
