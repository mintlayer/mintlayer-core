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

use utils::default_data_dir::PrepareDataDirError;

#[derive(thiserror::Error, Debug)]
pub enum WalletCliError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Wallet error: {0}")]
    WalletError(wallet::wallet::WalletError),
    #[error("Console IO error: {0}")]
    ConsoleIoError(std::io::Error),
    #[error("File '{0}' IO error: {1}")]
    FileIoError(PathBuf, std::io::Error),
    #[error("History file {0} I/O error: {1}")]
    HistoryFileError(PathBuf, std::io::Error),
    #[error(
        "RPC authentication cookie-file {0} read error: {1}. Please make sure the node is started."
    )]
    CookieFileReadError(PathBuf, std::io::Error),
    #[error("Prepare data dir error: {0}")]
    PrepareData(PrepareDataDirError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Invalid quoting")]
    InvalidQuoting,
    #[error("{0}")]
    InvalidCommandInput(clap::Error),
    #[error("Invalid mnemonic")]
    InvalidMnemonic(wallet::WalletError),
    #[error("Cancelled")]
    Cancelled,
    #[error("Quit")]
    Exit,
}
