// Copyright (c) 2025 RBB S.r.l
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

use core::fmt;

use serialization::{Decode, Encode};

/// This is the data that will be stored in the wallet db.
#[cfg(feature = "trezor")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TrezorData {
    pub device_id: String,
    pub device_name: String,
}

/// All the info we may want to know about a Trezor device.
#[cfg(feature = "trezor")]
#[derive(Debug, Clone)]
pub struct TrezorFullInfo {
    pub device_id: String,
    pub device_name: String,
    pub firmware_version: semver::Version,
}

#[cfg(feature = "trezor")]
impl From<TrezorFullInfo> for TrezorData {
    fn from(info: TrezorFullInfo) -> Self {
        Self {
            device_id: info.device_id,
            device_name: info.device_name,
        }
    }
}

#[cfg(feature = "ledger")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum LedgerModel {
    NanoS,
    NanoSPlus,
    NanoX,
    Stax,
    Unknown(u16),
}

impl fmt::Display for LedgerModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerModel::NanoS => write!(f, "Nano S"),
            LedgerModel::NanoSPlus => write!(f, "Nano S Plus"),
            LedgerModel::NanoX => write!(f, "Nano X"),
            LedgerModel::Stax => write!(f, "Stax"),
            LedgerModel::Unknown(id) => write!(f, "Unknown({})", id),
        }
    }
}

/// This is the data that will be stored in the wallet db.
#[cfg(feature = "ledger")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct LedgerData {}

/// All the info we may want to know about a Ledger device.
#[cfg(feature = "ledger")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct LedgerFullInfo {
    pub app_version: String,
    pub model: LedgerModel,
}

#[cfg(feature = "ledger")]
impl From<LedgerFullInfo> for LedgerData {
    fn from(_value: LedgerFullInfo) -> Self {
        Self {}
    }
}

/// This is the data that will be stored in the wallet db.
#[derive(Debug, Clone, Encode, Decode)]
pub enum HardwareWalletData {
    #[cfg(feature = "trezor")]
    #[codec(index = 0)]
    Trezor(TrezorData),
    #[cfg(feature = "ledger")]
    #[codec(index = 1)]
    Ledger(LedgerData),
}

/// All the info we may want to know about a hardware wallet.
#[derive(Debug, Clone)]
pub enum HardwareWalletFullInfo {
    #[cfg(feature = "trezor")]
    Trezor(TrezorFullInfo),
    #[cfg(feature = "ledger")]
    Ledger(LedgerFullInfo),
}

impl From<HardwareWalletFullInfo> for HardwareWalletData {
    fn from(info: HardwareWalletFullInfo) -> Self {
        match info {
            #[cfg(feature = "trezor")]
            HardwareWalletFullInfo::Trezor(trezor_data) => Self::Trezor(trezor_data.into()),
            #[cfg(feature = "ledger")]
            HardwareWalletFullInfo::Ledger(ledger_data) => Self::Ledger(ledger_data.into()),
        }
    }
}
