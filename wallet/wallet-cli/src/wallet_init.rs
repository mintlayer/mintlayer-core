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

use dialoguer::theme::ColorfulTheme;
use wallet::wallet::Language;

use crate::{cli_println, errors::WalletCliError, helpers::select_helper, output::OutputContext};

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

pub fn get_new_wallet_mnemonic(
    language: Language,
    output: &OutputContext,
    theme: &ColorfulTheme,
) -> Result<wallet::wallet::Mnemonic, WalletCliError> {
    let action = select_helper(
        theme,
        "Wallet is not initialized",
        &[ImportMnemonic::Generate, ImportMnemonic::Import, ImportMnemonic::Cancel],
    )?;

    let mnemonic = match action {
        ImportMnemonic::Generate => {
            let mnemonic = wallet::wallet::generate_new_mnemonic(language);
            cli_println!(output, "New mnemonic: {}", mnemonic.to_string());
            cli_println!(
                output,
                "Please write it somewhere safe to be able to restore your wallet."
            );
            mnemonic
        }
        ImportMnemonic::Import => {
            let mnemonic: String = dialoguer::Input::with_theme(theme)
                .with_prompt("Mnemonic")
                .interact_text()
                .map_err(WalletCliError::ConsoleIoError)?;
            wallet::wallet::parse_mnemonic(language, &mnemonic)
                .map_err(WalletCliError::InvalidMnemonic)?
        }
        ImportMnemonic::Cancel => return Err(WalletCliError::Cancelled),
    };

    Ok(mnemonic)
}
