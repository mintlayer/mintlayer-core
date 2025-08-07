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

impl From<TrezorFullInfo> for TrezorData {
    fn from(info: TrezorFullInfo) -> Self {
        Self {
            device_id: info.device_id,
            device_name: info.device_name,
        }
    }
}

/// This is the data that will be stored in the wallet db.
#[derive(Debug, Clone, Encode, Decode)]
pub enum HardwareWalletData {
    #[cfg(feature = "trezor")]
    #[codec(index = 0)]
    Trezor(TrezorData),
}

/// All the info we may want to know about a hardware wallet.
#[derive(Debug, Clone)]
pub enum HardwareWalletFullInfo {
    #[cfg(feature = "trezor")]
    Trezor(TrezorFullInfo),
}

impl From<HardwareWalletFullInfo> for HardwareWalletData {
    fn from(info: HardwareWalletFullInfo) -> Self {
        match info {
            #[cfg(feature = "trezor")]
            HardwareWalletFullInfo::Trezor(trezor_data) => Self::Trezor(trezor_data.into()),
        }
    }
}
