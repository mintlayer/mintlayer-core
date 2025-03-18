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

use utils::cookie::LoadCookieError;
use wallet_cli_commands::WalletCliCommandError;
use wallet_rpc_client::rpc_client::WalletRpcError;
use wallet_rpc_lib::types::NodeInterface;

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
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Error converting to json: {0}")]
    SerdeJsonFormatError(#[from] serde_json::Error),
    #[error("{0}")]
    WalletClientRpcError(#[from] WalletRpcError),
    #[error("{0}")]
    WalletCommandError(#[from] WalletCliCommandError<N>),
    #[error("Unexpected interaction on startup commands")]
    UnexpectedInteraction,
}
