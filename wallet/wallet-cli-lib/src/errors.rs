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
use utils::cookie::LoadCookieError;

#[derive(thiserror::Error, Debug)]
pub enum WalletCliError {
    #[error("Controller error: {0}")]
    Controller(wallet_controller::ControllerError<wallet_controller::NodeRpcClient>),
    #[error("RPC error: {0}")]
    RpcError(node_comm::rpc_client::NodeRpcError),
    #[error("File {0} I/O error: {1}")]
    FileError(PathBuf, std::io::Error),
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
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(wallet_controller::mnemonic::Error),
    #[error("Wallet file already open")]
    WalletFileAlreadyOpen,
    #[error("Please open or create wallet file first")]
    NoWallet,
    #[error("Please select an account to use")]
    NoSelectedAccount,
    #[error("Account not found for index: {0}")]
    AccountNotFound(U31),
}
