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

use serialization::{Decode, Encode};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub enum WalletType {
    #[codec(index = 0)]
    Cold,
    #[codec(index = 1)]
    Hot,
    #[cfg(feature = "trezor")]
    #[codec(index = 2)]
    Trezor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WalletControllerMode {
    Cold,
    Hot,
}

impl Display for WalletControllerMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hot => write!(f, "Hot"),
            Self::Cold => write!(f, "Cold"),
        }
    }
}

impl WalletType {
    /// Check if current Wallet type is compatible to be opened as the other wallet type
    pub fn is_compatible(&self, other: WalletControllerMode) -> bool {
        match (*self, other) {
            (Self::Hot, WalletControllerMode::Hot) | (Self::Cold, WalletControllerMode::Cold) => {
                true
            }
            (Self::Hot, WalletControllerMode::Cold) | (Self::Cold, WalletControllerMode::Hot) => {
                false
            }
            #[cfg(feature = "trezor")]
            (Self::Trezor, WalletControllerMode::Hot) => true,
            #[cfg(feature = "trezor")]
            (Self::Trezor, WalletControllerMode::Cold) => false,
        }
    }
}

impl From<WalletControllerMode> for WalletType {
    fn from(value: WalletControllerMode) -> Self {
        match value {
            WalletControllerMode::Hot => WalletType::Hot,
            WalletControllerMode::Cold => WalletType::Cold,
        }
    }
}

impl Display for WalletType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hot => write!(f, "Hot"),
            Self::Cold => write!(f, "Cold"),
            #[cfg(feature = "trezor")]
            Self::Trezor => write!(f, "Trezor"),
        }
    }
}
