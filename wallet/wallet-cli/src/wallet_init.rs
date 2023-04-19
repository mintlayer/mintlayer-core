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

use std::sync::Arc;

use common::chain::ChainConfig;
use dialoguer::theme::ColorfulTheme;
use wallet::Wallet;

use crate::{
    cli_println, errors::WalletCliError, helpers::select_helper, output::OutputContext, DefWallet,
};

#[derive(Clone, Copy)]
enum ImportMnemonic {
    Generate,
    Import,
    Cancel,
}

impl From<ImportMnemonic> for &str {
    fn from(val: ImportMnemonic) -> Self {
        match val {
            ImportMnemonic::Generate => "Generate new mnemonic",
            ImportMnemonic::Import => "Import mnemonic",
            ImportMnemonic::Cancel => "Cancel",
        }
    }
}

pub fn new_wallet(
    output: &OutputContext,
    chain_config: Arc<ChainConfig>,
    db: Arc<wallet_storage::Store<wallet_storage::DefaultBackend>>,
    theme: &ColorfulTheme,
) -> Result<DefWallet, WalletCliError> {
    let action = select_helper(
        theme,
        "Wallet is not initialized",
        &[ImportMnemonic::Generate, ImportMnemonic::Import, ImportMnemonic::Cancel],
    )?;

    let mnemonic: String = match action {
        ImportMnemonic::Generate => {
            let new_mnemonoc = wallet::wallet::generate_new_mnemonic();
            cli_println!(output, "New mnemonic: {}", new_mnemonoc.to_string());
            cli_println!(
                output,
                "Please write it somewhere safe to be able to restore your wallet."
            );
            new_mnemonoc.to_string()
        }
        ImportMnemonic::Import => dialoguer::Input::with_theme(theme)
            .with_prompt("Mnemonic")
            .interact_text()
            .map_err(WalletCliError::ConsoleIoError)?,
        ImportMnemonic::Cancel => return Err(WalletCliError::Cancelled),
    };

    // TODO: Add optional passphrase

    Wallet::new_wallet(Arc::clone(&chain_config), db, &mnemonic, None)
        .map_err(WalletCliError::WalletError)
}
