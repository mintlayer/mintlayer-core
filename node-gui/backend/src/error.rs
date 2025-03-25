// Copyright (c) 2023 RBB S.r.l
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

use super::{account_id::AccountId, messages::WalletId};

#[derive(thiserror::Error, Debug, Clone)]
pub enum BackendError {
    #[error("Wallet error: {0}")]
    WalletError(String),
    #[error("Conversion to dehexified json error: {0}")]
    ConversionToDehexifiedJsonError(String),
    #[error("Unknown wallet index: {0:?}")]
    UnknownWalletIndex(WalletId),
    #[error("Unknown account index: {0:?}/{0:?}")]
    UnknownAccountIndex(WalletId, AccountId),
    #[error("Invalid address: {0}")]
    AddressError(String),
    #[error("Invalid address index: {0}")]
    InvalidAddressIndex(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Invalid pledge amount: {0}")]
    InvalidPledgeAmount(String),
    #[error("Invalid cost per block amount: {0}")]
    InvalidCostPerBlockAmount(String),
    #[error("Failed to parse margin per thousand: {0}. The decimal must be in the range [0.001,1.000] or [0.1%,100%]")]
    InvalidMarginPerThousand(String),
    #[error("Unsupported operation by a cold wallet")]
    ColdWallet,
    #[error("Cannot interact with a hot wallet when in Cold wallet mode")]
    HotNotSupported,
    #[error("Cannot use a Trezor wallet in a Cold wallet mode")]
    ColdTrezorNotSupported,
    #[error("Invalid console command: {0}")]
    InvalidConsoleCommand(String),
    #[error("Empty console command")]
    EmptyConsoleCommand,
}
