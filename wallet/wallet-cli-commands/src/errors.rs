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

use crypto::key::hdkd::u31::U31;
use node_comm::node_traits::NodeInterface;
use utils::qrcode::QrCodeError;
use wallet_controller::types::GenericCurrencyTransferToTxOutputConversionError;
use wallet_rpc_client::{handles_client::WalletRpcHandlesClientError, rpc_client::WalletRpcError};
use wallet_rpc_lib::RpcError;

#[derive(thiserror::Error, derive_more::Debug)]
pub enum WalletCliCommandError<N: NodeInterface> {
    #[error("Invalid quoting")]
    InvalidQuoting,
    #[error("{0}")]
    InvalidCommandInput(clap::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Please open or create a wallet file first")]
    NoWallet,
    #[error("Account not found for index: {0}")]
    AccountNotFound(U31),
    #[error("QR Code encoding error: {0}")]
    QrCodeEncoding(#[from] QrCodeError),
    #[error("Error converting to json: {0}")]
    SerdeJsonFormatError(#[from] serde_json::Error),
    #[error("{0}")]
    WalletRpcError(#[from] RpcError<N>),
    #[error("{0}")]
    WalletHandlessRpcError(#[from] WalletRpcHandlesClientError<N>),
    #[error("{0}")]
    WalletClientRpcError(#[from] WalletRpcError),
    #[error("A new wallet has been opened between commands")]
    NewWalletWasOpened,
    #[error("A different wallet than the existing one has been opened between commands")]
    DifferentWalletWasOpened,
    #[error("The wallet has been closed between commands")]
    ExistingWalletWasClosed,
    #[error("Invalid tx output: {0}")]
    InvalidTxOutput(GenericCurrencyTransferToTxOutputConversionError),
}
