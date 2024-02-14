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

use std::path::PathBuf;

use crypto::key::hdkd::u31::U31;
use utils::{cookie::LoadCookieError, qrcode::QrCodeError};
use wallet::WalletError;
use wallet_rpc_client::{handles_client::WalletRpcHandlesClientError, rpc_client::WalletRpcError};
use wallet_rpc_lib::types::NodeInterface;
use wallet_rpc_lib::RpcError;

#[derive(thiserror::Error, Debug)]
pub enum WalletCliError<N: NodeInterface> {
    #[error("File {0} I/O error: {1}")]
    FileError(PathBuf, String),
    #[error(
        "RPC authentication cookie-file read error: {0}. Please make sure the node is started."
    )]
    CookieFileReadError(#[from] LoadCookieError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Invalid quoting")]
    InvalidQuoting,
    #[error("{0}")]
    InvalidCommandInput(clap::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Wallet file already open")]
    WalletFileAlreadyOpen,
    #[error("Please open or create wallet file first")]
    NoWallet,
    #[error("Please select an account to use")]
    NoSelectedAccount,
    #[error("Account not found for index: {0}")]
    AccountNotFound(U31),
    #[error("QR Code encoding error: {0}")]
    QrCodeEncoding(#[from] QrCodeError),
    #[error("Retrieving addresses with usage failed for account {0}: {1}")]
    AddressesRetrievalFailed(U31, String),
    #[error("Error converting to json: {0}")]
    SerdeJsonFormatError(#[from] serde_json::Error),
    #[error("{0}")]
    WalletRpcError(#[from] RpcError<N>),
    #[error("Failed to convert to signed transaction: {0}")]
    FailedToConvertToSignedTransaction(#[from] WalletError),
    #[error("{0}")]
    WalletHandlessRpcError(#[from] WalletRpcHandlesClientError<N>),
    #[error("{0}")]
    WalletClientRpcError(#[from] WalletRpcError),
}
