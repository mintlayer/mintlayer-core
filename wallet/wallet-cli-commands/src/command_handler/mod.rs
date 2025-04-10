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

mod local_state;

use std::{fmt::Write, str::FromStr};

use common::{
    address::Address,
    chain::{
        config::checkpoints_data::print_block_heights_ids_as_checkpoints_data, ChainConfig,
        Destination, SignedTransaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Idable as _, H256},
    text_summary::TextSummary,
};
use crypto::key::hdkd::u31::U31;
use itertools::Itertools;
use mempool::tx_options::TxOptionsOverrides;
use node_comm::node_traits::NodeInterface;
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use utils::{
    ensure,
    qrcode::{QrCode, QrCodeError},
};
use wallet::version::get_version;
use wallet_controller::types::GenericTokenTransfer;
use wallet_rpc_client::wallet_rpc_traits::{PartialOrSignedTx, WalletInterface};
use wallet_rpc_lib::types::{
    Balances, ComposedTransaction, ControllerConfig, HardwareWalletType, MnemonicInfo,
    NewSubmittedTransaction, NftMetadata, RpcInspectTransaction, RpcNewTransaction,
    RpcSignatureStats, RpcSignatureStatus, RpcStandaloneAddressDetails, RpcValidatedSignatures,
    TokenMetadata,
};

use wallet_types::partially_signed_transaction::PartiallySignedTransaction;

use crate::{
    errors::WalletCliCommandError, helper_types::parse_generic_token_transfer,
    CreateWalletDeviceSelectMenu, ManageableWalletCommand, OpenWalletDeviceSelectMenu,
    OpenWalletSubCommand, WalletManagementCommand,
};

use self::local_state::WalletWithState;

use super::{
    helper_types::{
        format_delegation_info, format_pool_info, parse_coin_output, parse_token_supply,
        parse_utxo_outpoint, CliForceReduce, CliUtxoState,
    },
    ColdWalletCommand, ConsoleCommand, WalletCommand,
};

pub struct CommandHandler<W> {
    config: ControllerConfig,

    wallet: WalletWithState<W>,

    no_qr: bool,
}

impl<W, E> CommandHandler<W>
where
    W: WalletInterface<Error = E> + Send + Sync + 'static,
{
    pub async fn new(config: ControllerConfig, wallet: W, no_qr: Option<bool>) -> Self {
        CommandHandler {
            config,
            wallet: WalletWithState::new(wallet).await,
            no_qr: no_qr.unwrap_or(false),
        }
    }

    pub async fn rpc_completed(&self) {
        self.wallet.rpc_completed().await
    }

    async fn set_selected_account<N: NodeInterface>(
        &mut self,
        account_index: U31,
    ) -> Result<(), WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        let state = self.wallet.get_mut_state().await?;

        if account_index.into_u32() as usize >= state.num_accounts() {
            return Err(WalletCliCommandError::AccountNotFound(account_index));
        }

        state.set_selected_account(account_index);
        Ok(())
    }

    async fn repl_status<N: NodeInterface>(&mut self) -> Result<String, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        let status = match self.wallet.get_opt_state().await? {
            Some(state) => {
                if state.num_accounts() > 1 {
                    match state.get_selected_acc_name() {
                        Some(Some(name)) => format!("(Account {})", name),
                        _ => format!("(Account No. {})", state.selected_account()),
                    }
                } else {
                    String::new()
                }
            }
            None => String::new(),
        };

        Ok(status)
    }

    pub fn new_tx_command(new_tx: RpcNewTransaction, chain_config: &ChainConfig) -> ConsoleCommand {
        let status_text = if new_tx.broadcasted {
            let summary = new_tx.tx.take().transaction().text_summary(chain_config);
            format!(
                "{summary}\nThe transaction was submitted successfully with ID:\n{}",
                id_to_hex_string(*new_tx.tx_id.as_hash())
            )
        } else {
            let hex = new_tx.tx.to_string();
            let summary = new_tx.tx.take().transaction().text_summary(chain_config);

            format!("{summary}\nThe transaction was created and ready to be submitted:\n{hex}",)
        };

        ConsoleCommand::Print(status_text)
    }

    pub fn new_tx_submitted_command(new_tx: NewSubmittedTransaction) -> ConsoleCommand {
        let status_text = format!(
            "The transaction was submitted successfully with ID:\n{}",
            id_to_hex_string(*new_tx.tx_id.as_hash())
        );
        ConsoleCommand::Print(status_text)
    }

    async fn non_empty_wallet<N: NodeInterface>(&mut self) -> Result<&W, WalletCliCommandError<N>> {
        self.wallet.get_wallet_with_acc().await.map(|(w, _)| w)
    }

    async fn wallet<N: NodeInterface>(&mut self) -> Result<&W, WalletCliCommandError<N>> {
        self.wallet.get_wallet().await
    }

    async fn handle_wallet_management_command<N: NodeInterface>(
        &mut self,
        command: WalletManagementCommand,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        match command {
            WalletManagementCommand::CreateWallet { wallet } => {
                let (wallet_path, wallet_args) = wallet.into_path_and_wallet_args();

                let response =
                    self.wallet().await?.create_wallet(wallet_path.clone(), wallet_args).await?;

                if let Some(devices) = response.multiple_devices_available {
                    match devices {
                        wallet_rpc_lib::types::MultipleDevicesAvailable::Trezor { devices } => {
                            let choices =
                                CreateWalletDeviceSelectMenu::new(devices, wallet_path, false);
                            return Ok(ConsoleCommand::ChoiceMenu(Box::new(choices)));
                        }
                    }
                }

                self.wallet.update_wallet::<N>().await;

                let msg = match response.mnemonic {
                    MnemonicInfo::NewlyGenerated { mnemonic } => {
                        format!(
                            "New wallet created successfully\nYour mnemonic: {}\n\
                        Please write it somewhere safe to be able to restore your wallet. \
                        It's recommended that you attempt to recover the wallet now as practice\
                        to check that you arrive at the same addresses, \
                        to ensure that you have done everything correctly.
                        ",
                            mnemonic
                        )
                    }
                    MnemonicInfo::UserProvided => "New wallet created successfully".to_owned(),
                };

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: msg,
                })
            }

            WalletManagementCommand::RecoverWallet { wallet } => {
                let (wallet_path, wallet_args) = wallet.into_path_and_wallet_args();

                let response =
                    self.wallet().await?.recover_wallet(wallet_path.clone(), wallet_args).await?;

                if let Some(devices) = response.multiple_devices_available {
                    match devices {
                        wallet_rpc_lib::types::MultipleDevicesAvailable::Trezor { devices } => {
                            let choices =
                                CreateWalletDeviceSelectMenu::new(devices, wallet_path, true);
                            return Ok(ConsoleCommand::ChoiceMenu(Box::new(choices)));
                        }
                    }
                }

                self.wallet.update_wallet::<N>().await;

                let msg = "Wallet recovered successfully";

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: msg.to_owned(),
                })
            }

            WalletManagementCommand::OpenWallet { wallet } => {
                let (wallet_path, encryption_password, force_change_wallet_type, hardware_wallet) =
                    match wallet {
                        OpenWalletSubCommand::Software {
                            wallet_path,
                            encryption_password,
                            force_change_wallet_type,
                        } => (
                            wallet_path,
                            encryption_password,
                            force_change_wallet_type,
                            None,
                        ),
                        OpenWalletSubCommand::Trezor {
                            wallet_path,
                            encryption_password,
                            device_id,
                        } => (
                            wallet_path,
                            encryption_password,
                            false,
                            Some(HardwareWalletType::Trezor { device_id }),
                        ),
                    };

                let response = self
                    .wallet()
                    .await?
                    .open_wallet(
                        wallet_path.clone(),
                        encryption_password.clone(),
                        Some(force_change_wallet_type),
                        hardware_wallet,
                    )
                    .await?;

                // In the case that the user has reset the device that was used to create the
                // wallet file that is now being opened, the device can have a different device id.
                // So in the case of multiple Hardware wallets connected it cannot decide which one
                // to use, and we fall back to asking the user to choose.
                if let wallet_rpc_lib::types::OpenedWallet::MultipleDevicesAvailable { available } =
                    response
                {
                    match available {
                        wallet_rpc_lib::types::MultipleDevicesAvailable::Trezor { devices } => {
                            let choices = OpenWalletDeviceSelectMenu::new(
                                devices,
                                wallet_path,
                                encryption_password,
                            );
                            return Ok(ConsoleCommand::ChoiceMenu(Box::new(choices)));
                        }
                    }
                }
                self.wallet.update_wallet::<N>().await;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Wallet loaded successfully".to_owned(),
                })
            }

            WalletManagementCommand::CloseWallet => {
                self.wallet().await?.close_wallet().await?;
                self.wallet.update_wallet::<N>().await;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Successfully closed the wallet.".to_owned(),
                })
            }
            WalletManagementCommand::RpcShutdownAndExit => {
                self.wallet.get_wallet_mut().await?.shutdown().await?;
                Ok(ConsoleCommand::Exit)
            }
            WalletManagementCommand::Exit => {
                self.wallet.get_wallet_mut().await?.exit().await?;
                Ok(ConsoleCommand::Exit)
            }
        }
    }

    async fn handle_cold_wallet_command<N: NodeInterface>(
        &mut self,
        command: ColdWalletCommand,
        chain_config: &ChainConfig,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        match command {
            ColdWalletCommand::WalletInfo => {
                let info = self.non_empty_wallet().await?.wallet_info().await?;
                let names = info
                    .account_names
                    .into_iter()
                    .enumerate()
                    .map(|(idx, name)| {
                        let name = name.map_or("None".into(), |name| format!("\"{name}\""));
                        format!("Account index: {idx}, Name: {name}")
                    })
                    .join("\n");

                Ok(ConsoleCommand::Print(format!("Wallet Accounts:\n{names}")))
            }

            ColdWalletCommand::EncryptPrivateKeys { password } => {
                self.non_empty_wallet().await?.encrypt_private_keys(password).await?;

                Ok(ConsoleCommand::Print(
                    "Successfully encrypted the private keys of the wallet.".to_owned(),
                ))
            }

            ColdWalletCommand::RemovePrivateKeysEncryption => {
                self.non_empty_wallet().await?.remove_private_key_encryption().await?;

                Ok(ConsoleCommand::Print(
                    "Successfully removed the encryption from the private keys.".to_owned(),
                ))
            }

            ColdWalletCommand::UnlockPrivateKeys { password } => {
                self.non_empty_wallet().await?.unlock_private_keys(password).await?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now unlocked.".to_owned(),
                ))
            }

            ColdWalletCommand::LockPrivateKeys => {
                self.non_empty_wallet().await?.lock_private_key_encryption().await?;

                Ok(ConsoleCommand::Print(
                    "Success. The wallet is now locked.".to_owned(),
                ))
            }

            ColdWalletCommand::ShowSeedPhrase => {
                let phrase = self.non_empty_wallet().await?.get_seed_phrase().await?;

                let msg = if let Some(phrase) = phrase {
                    if let Some(passphrase) = phrase.passphrase {
                        format!(
                            "The stored seed phrase is \"{}\"\nwith passphrase \"{}\"",
                            phrase.seed_phrase.join(" "),
                            passphrase
                        )
                    } else {
                        format!(
                            "The stored seed phrase is \"{}\"",
                            phrase.seed_phrase.join(" ")
                        )
                    }
                } else {
                    "No stored seed phrase for this wallet. This was your choice when you created the wallet as a security option. Make sure not to lose this wallet file if you don't have the seed-phrase stored elsewhere when you created the wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            ColdWalletCommand::PurgeSeedPhrase => {
                let phrase = self.non_empty_wallet().await?.purge_seed_phrase().await?;

                let msg = if let Some(phrase) = phrase {
                    let passphrase = if let Some(passphrase) = phrase.passphrase {
                        format!("\nwith passphrase: \"{passphrase}\"")
                    } else {
                        String::new()
                    };
                    format!("The seed phrase has been deleted, you can store it if you haven't done so yet: \"{}\"{passphrase}", phrase.seed_phrase.join(" "))
                } else {
                    "No stored seed phrase for this wallet.".into()
                };

                Ok(ConsoleCommand::Print(msg))
            }

            ColdWalletCommand::SetLookaheadSize {
                lookahead_size,
                i_know_what_i_am_doing,
            } => {
                let force_reduce = match i_know_what_i_am_doing {
                    Some(CliForceReduce::IKnowWhatIAmDoing) => true,
                    None => false,
                };

                self.non_empty_wallet()
                    .await?
                    .set_lookahead_size(lookahead_size, force_reduce)
                    .await?;

                Ok(ConsoleCommand::Print(
                    "Success. Lookahead size has been updated, will rescan the blockchain."
                        .to_owned(),
                ))
            }

            ColdWalletCommand::AddressQRCode { address } => {
                let addr: Address<Destination> = Address::from_string(chain_config, address)
                    .map_err(|_| {
                        WalletCliCommandError::InvalidInput("Invalid address".to_string())
                    })?;

                let qr_code_string = qrcode_or_error_string(&addr.to_string());
                Ok(ConsoleCommand::Print(qr_code_string))
            }

            ColdWalletCommand::NewAddress => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let address = wallet.issue_address(selected_account).await?;
                Ok(ConsoleCommand::Print(address.address))
            }

            ColdWalletCommand::RevealPublicKey { public_key_hash } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let public_key =
                    wallet.reveal_public_key(selected_account, public_key_hash).await?;
                Ok(ConsoleCommand::Print(
                    public_key.public_key_address.to_string(),
                ))
            }

            ColdWalletCommand::RevealPublicKeyHex { public_key_hash } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let public_key =
                    wallet.reveal_public_key(selected_account, public_key_hash).await?;
                Ok(ConsoleCommand::Print(
                    public_key.public_key_hex.hex_encode(),
                ))
            }

            ColdWalletCommand::ShowAddresses { include_change } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let addresses_with_usage =
                    wallet.get_issued_addresses(selected_account, include_change).await?;

                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row![
                        "Index",
                        "Purpose",
                        "Address",
                        "Is used in transaction history",
                        "Coins",
                    ]);

                    addresses_table.extend(addresses_with_usage.into_iter().map(|info| {
                        let is_used = if info.used { "Yes" } else { "No" };
                        let purpose = match info.purpose {
                            wallet_rpc_lib::types::RpcKeyPurpose::Change => "Change",
                            wallet_rpc_lib::types::RpcKeyPurpose::Receive => "Receive",
                        };

                        prettytable::row![
                            info.index,
                            purpose,
                            info.address,
                            is_used,
                            info.coins.decimal().to_string()
                        ]
                    }));

                    addresses_table
                };

                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            ColdWalletCommand::ShowStandaloneAddresses => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let addresses = wallet.get_standalone_addresses(selected_account).await?;

                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row!["Address", "Type", "Label",]);

                    addresses_table.extend(addresses.watch_only_addresses.into_iter().map(
                        |info| {
                            let label = info.label.unwrap_or_default();
                            let address_type = "Watch Only";
                            prettytable::row![info.address, address_type, label]
                        },
                    ));
                    addresses_table.extend(addresses.multisig_addresses.into_iter().map(|info| {
                        let label = info.label.unwrap_or_default();
                        let address_type = "Multisig";
                        prettytable::row![info.address, address_type, label]
                    }));
                    addresses_table.extend(addresses.private_key_addresses.into_iter().flat_map(
                        |info| {
                            let label = info.label.unwrap_or_default();
                            let address_type = "From Private key";
                            [
                                prettytable::row![info.public_key_hash, address_type, label],
                                prettytable::row![info.public_key, address_type, label],
                            ]
                        },
                    ));

                    addresses_table
                };

                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            ColdWalletCommand::ShowStandaloneAddressDetails { address } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let addr_details =
                    wallet.get_standalone_address_details(selected_account, address).await?;

                let label_str =
                    addr_details.label.map_or("None".into(), |label| format!("\"{label}\""));
                let mut output = match addr_details.details {
                    RpcStandaloneAddressDetails::WatchOnly => {
                        let has_private_key = "No";

                        format!(
                            "Address: {}, label: {}, has_private_key: {}\nBalances:\n",
                            addr_details.address, label_str, has_private_key
                        )
                    }
                    RpcStandaloneAddressDetails::FromPrivateKey => {
                        let has_private_key = "Yes";

                        format!(
                            "Address: {}, label: {}, has_private_key: {}\nBalances:\n",
                            addr_details.address, label_str, has_private_key
                        )
                    }
                    RpcStandaloneAddressDetails::Multisig {
                        min_required_signatures,
                        public_keys,
                    } => {
                        format!(
                            "Address: {}, label: {}, min_required_signatures: {}, public_keys: {}\nBalances:\n",
                            addr_details.address,
                            label_str,
                            min_required_signatures,
                            public_keys.iter().join(", ")
                        )
                    }
                };
                let (coins, tokens) = addr_details.balances.into_coins_and_tokens();
                let coins = coins.decimal();
                writeln!(&mut output, "Coins amount: {coins}\n")
                    .expect("Writing to a memory buffer should not fail");

                for (token_id, amount) in tokens {
                    let amount = amount.decimal();
                    writeln!(&mut output, "Token: {token_id} amount: {amount}")
                        .expect("Writing to a memory buffer should not fail");
                }
                output.pop();

                Ok(ConsoleCommand::Print(output))
            }

            ColdWalletCommand::NewVrfPublicKey => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let vrf_public_key = wallet.new_vrf_public_key(selected_account).await?;
                Ok(ConsoleCommand::Print(format!(
                    "New VRF public key: {} with index {}",
                    vrf_public_key.vrf_public_key, vrf_public_key.child_number
                )))
            }

            ColdWalletCommand::GetVrfPublicKey => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let addresses_with_usage = wallet.get_vrf_public_key(selected_account).await?;
                let addresses_table = {
                    let mut addresses_table = prettytable::Table::new();
                    addresses_table.set_titles(prettytable::row![
                        "Index",
                        "Address",
                        "Is used in transaction history",
                    ]);

                    addresses_table.extend(addresses_with_usage.into_iter().map(|info| {
                        let is_used = if info.used { "Yes" } else { "No" };
                        prettytable::row![info.child_number, info.vrf_public_key, is_used]
                    }));

                    addresses_table
                };
                Ok(ConsoleCommand::Print(addresses_table.to_string()))
            }

            ColdWalletCommand::GetLegacyVrfPublicKey => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let legacy_pubkey = wallet.get_legacy_vrf_public_key(selected_account).await?;
                Ok(ConsoleCommand::Print(legacy_pubkey.vrf_public_key))
            }

            ColdWalletCommand::SignRawTransaction { transaction } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result =
                    wallet.sign_raw_transaction(selected_account, transaction, self.config).await?;

                let output_str = match result.transaction {
                    PartialOrSignedTx::Signed(signed_tx) => {
                        let summary = signed_tx.transaction().text_summary(chain_config);
                        let result_hex: HexEncoded<SignedTransaction> = signed_tx.into();

                        let qr_code_string = (!self.no_qr)
                            .then(|| {
                                let qr_code = qrcode_or_error_string(&result_hex.to_string());
                                format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                            })
                            .unwrap_or_default();

                        format!(
                            "The transaction has been fully signed and is ready to be broadcast to network. \
                             You can use the command `node-submit-transaction` in a wallet connected to the internet (this one or elsewhere). \
                             Pass the following data to the wallet to broadcast:\n\n{result_hex}\
                             {qr_code_string}\n\n{summary}")
                    }
                    PartialOrSignedTx::Partial(partially_signed_tx) => {
                        let result_hex: HexEncoded<PartiallySignedTransaction> =
                            partially_signed_tx.into();

                        let qr_code_string = (!self.no_qr)
                            .then(|| {
                                let qr_code = qrcode_or_error_string(&result_hex.to_string());
                                format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                            })
                            .unwrap_or_default();

                        let prev_sigs = result
                            .previous_signatures
                            .iter()
                            .enumerate()
                            .map(format_signature_status)
                            .join(", ");
                        let current_sigs = result
                            .current_signatures
                            .iter()
                            .enumerate()
                            .map(format_signature_status)
                            .join(", ");

                        format!(
                            "Not all transaction inputs have been signed. This wallet does not have all the keys for that.\n\
                             The signatures states before signing were:\n{prev_sigs}\n\
                             and the current signature states are:\n{current_sigs}\n\
                             Pass the following string into the wallet that has appropriate keys for the inputs to sign what is left:\n\n{result_hex}\
                             {qr_code_string}"
                        )
                    }
                };

                Ok(ConsoleCommand::Print(output_str))
            }

            ColdWalletCommand::SignChallegeHex {
                message: challenge,
                address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result =
                    wallet.sign_challenge_hex(selected_account, challenge, address).await?;

                let qr_code_string = (!self.no_qr)
                    .then(|| {
                        let qr_code = qrcode_or_error_string(&result);
                        format!("\n\nThe following qr code also contains the signature for easy transport:\n{qr_code}")
                    })
                    .unwrap_or_default();

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex encoded signature is\n\n{result}{qr_code_string}",
                )))
            }

            ColdWalletCommand::SignChallege {
                message: challenge,
                address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result = wallet.sign_challenge(selected_account, challenge, address).await?;

                let qr_code_string = (!self.no_qr)
                    .then(|| {
                        let qr_code = qrcode_or_error_string(&result);
                        format!("\n\nThe following qr code also contains the signature for easy transport:\n{qr_code}")
                    })
                    .unwrap_or_default();

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex encoded signature is\n\n{result}{qr_code_string}",
                )))
            }

            ColdWalletCommand::VerifyChallengeHex {
                message,
                signed_challenge,
                address,
            } => {
                self.non_empty_wallet()
                    .await?
                    .verify_challenge_hex(message, signed_challenge, address)
                    .await?;

                Ok(ConsoleCommand::Print(
                    "The provided signature is correct".to_string(),
                ))
            }

            ColdWalletCommand::VerifyChallenge {
                message,
                signed_challenge,
                address,
            } => {
                self.non_empty_wallet()
                    .await?
                    .verify_challenge(message, signed_challenge, address)
                    .await?;

                Ok(ConsoleCommand::Print(
                    "The provided signature is correct".to_string(),
                ))
            }

            ColdWalletCommand::Version => Ok(ConsoleCommand::Print(get_version())),
            ColdWalletCommand::PrintHistory => Ok(ConsoleCommand::PrintHistory),
            ColdWalletCommand::ClearScreen => Ok(ConsoleCommand::ClearScreen),
            ColdWalletCommand::ClearHistory => Ok(ConsoleCommand::ClearHistory),
        }
    }

    pub async fn handle_wallet_command<N: NodeInterface>(
        &mut self,
        chain_config: &ChainConfig,
        command: WalletCommand,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        match command {
            WalletCommand::ColdCommands(command) => {
                self.handle_cold_wallet_command(command, chain_config).await
            }

            WalletCommand::ConfigBroadcast { broadcast } => {
                self.config.broadcast_to_mempool = broadcast;
                Ok(ConsoleCommand::Print(format!(
                    "Broadcast to Mempool set to: {broadcast:?}"
                )))
            }

            WalletCommand::ChainstateInfo => {
                let info = self.wallet().await?.chainstate_info().await?;
                Ok(ConsoleCommand::Print(format!("{info:#?}")))
            }

            WalletCommand::BestBlock => {
                let id = self.wallet().await?.node_best_block_id().await?;
                Ok(ConsoleCommand::Print(id.hex_encode()))
            }

            WalletCommand::BestBlockHeight => {
                let height = self.wallet().await?.node_best_block_height().await?;
                Ok(ConsoleCommand::Print(height.to_string()))
            }

            WalletCommand::BestBlockTimestamp => {
                let timestamp = self.wallet().await?.chainstate_info().await?.best_block_timestamp;
                Ok(ConsoleCommand::Print(format!(
                    "{} ({})",
                    timestamp,
                    timestamp.into_time()
                )))
            }

            WalletCommand::BlockId { height } => {
                let hash = self.wallet().await?.node_block_id(height).await?;
                match hash {
                    Some(id) => Ok(ConsoleCommand::Print(id.hex_encode())),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GetBlock { hash } => {
                let hash = self.wallet().await?.node_block(hash).await?;
                match hash {
                    Some(block) => Ok(ConsoleCommand::Print(block)),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::GenerateBlock { transactions } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.node_generate_block(selected_account, transactions).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GenerateBlocks { block_count } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.node_generate_blocks(selected_account, block_count).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::FindTimestampsForStaking {
                pool_id,
                min_height,
                max_height,
                seconds_to_check_for_height,
                check_all_timestamps_between_blocks,
            } => {
                let timestamp_map = self
                    .wallet()
                    .await?
                    .node_find_timestamps_for_staking(
                        pool_id,
                        min_height,
                        Some(max_height),
                        seconds_to_check_for_height,
                        check_all_timestamps_between_blocks.to_bool(),
                    )
                    .await?;
                Ok(ConsoleCommand::Print(format!("{timestamp_map:#?}")))
            }

            WalletCommand::GetBlockIdsAsCheckpoints {
                start_height,
                end_height,
                step,
            } => {
                let block_ids = self
                    .wallet()
                    .await?
                    .node_get_block_ids_as_checkpoints(start_height, end_height, step)
                    .await?;

                Ok(ConsoleCommand::Print(
                    print_block_heights_ids_as_checkpoints_data(&block_ids),
                ))
            }

            WalletCommand::CreateNewAccount { name } => {
                let new_acc = self.non_empty_wallet().await?.create_account(name).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: format!(
                        "Success, the new account index is: {}",
                        new_acc.account,
                    ),
                })
            }

            WalletCommand::RenameAccount { name } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.rename_account(selected_account, name).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Success, the account name has been successfully renamed".into(),
                })
            }

            WalletCommand::StandaloneAddressLabelRename { address, label } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.standalone_address_label_rename(selected_account, address, label).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Success, the label has been changed.".into(),
                })
            }

            WalletCommand::AddStandaloneKey {
                address,
                label,
                no_rescan,
            } => {
                let no_rescan = no_rescan.unwrap_or(false);
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet
                    .add_standalone_address(selected_account, address, label, no_rescan)
                    .await?;

                let output = if no_rescan {
                    "Success, the new address has been added to the account."
                } else {
                    "Success, the new address has been added to the account.\nRescanning the blockchain to detect balance in added new addresses"
                };

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: output.into(),
                })
            }

            WalletCommand::AddStandalonePrivateKey {
                hex_private_key,
                label,
                no_rescan,
            } => {
                let no_rescan = no_rescan.unwrap_or(false);
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet
                    .add_standalone_private_key(selected_account, hex_private_key, label, no_rescan)
                    .await?;

                let output = if no_rescan {
                    "Success, the new private key has been added to the account."
                } else {
                    "Success, the new private key has been added to the account.\nRescanning the blockchain to detect balance in added new addresses"
                };

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: output.into(),
                })
            }

            WalletCommand::AddStandaloneMultisig {
                min_required_signatures,
                public_keys,
                label,
                no_rescan,
            } => {
                let no_rescan = no_rescan.unwrap_or(false);
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let multisig_address = wallet
                    .add_standalone_multisig(
                        selected_account,
                        min_required_signatures,
                        public_keys,
                        label,
                        no_rescan,
                    )
                    .await?;

                let output = if no_rescan {
                    format!("Success. The following new multisig address has been added to the account\n{multisig_address}")
                } else {
                    format!("Success. The following new multisig address has been added to the account\n{multisig_address}\nRescanning the blockchain to detect balance in added new addresses")
                };

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: output,
                })
            }

            WalletCommand::ListMultisigUtxo {
                utxo_type,
                with_locked,
                utxo_states,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let utxos = wallet
                    .get_multisig_utxos(
                        selected_account,
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await?;
                Ok(ConsoleCommand::Print(
                    serde_json::to_string(&utxos).expect("ok"),
                ))
            }

            WalletCommand::SelectAccount { account_index } => {
                self.set_selected_account(account_index).await?;

                Ok(ConsoleCommand::SetStatus {
                    status: self.repl_status().await?,
                    print_message: "Success".into(),
                })
            }

            WalletCommand::StartStaking => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.start_staking(selected_account).await?;
                Ok(ConsoleCommand::Print(
                    "Staking started successfully".to_owned(),
                ))
            }

            WalletCommand::StopStaking => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.stop_staking(selected_account).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::StakingStatus => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let status = wallet.staking_status(selected_account).await?;
                let status = match status {
                    wallet_rpc_lib::types::StakingStatus::Staking => "Staking",
                    wallet_rpc_lib::types::StakingStatus::NotStaking => "Not staking",
                };
                Ok(ConsoleCommand::Print(status.to_string()))
            }

            WalletCommand::StakePoolBalance { pool_id } => {
                let balance_opt =
                    self.non_empty_wallet().await?.stake_pool_balance(pool_id).await?;
                match balance_opt.balance {
                    Some(balance) => Ok(ConsoleCommand::Print(balance)),
                    None => Ok(ConsoleCommand::Print("Not found".to_owned())),
                }
            }

            WalletCommand::SubmitBlock { block } => {
                self.wallet().await?.submit_block(block).await?;
                Ok(ConsoleCommand::Print(
                    "The block was submitted successfully".to_owned(),
                ))
            }

            WalletCommand::SubmitTransaction {
                transaction,
                do_not_store,
            } => {
                let new_tx = self
                    .non_empty_wallet()
                    .await?
                    .submit_raw_transaction(
                        transaction,
                        do_not_store,
                        TxOptionsOverrides::default(),
                    )
                    .await?;
                Ok(Self::new_tx_submitted_command(new_tx))
            }

            WalletCommand::TransactionCompose {
                outputs,
                utxos,
                only_transaction,
            } => {
                let outputs: Vec<TxOutput> = outputs
                    .iter()
                    .map(|input| parse_coin_output(input, chain_config))
                    .collect::<Result<Vec<_>, WalletCliCommandError<N>>>()?;

                let input_utxos: Vec<UtxoOutPoint> = utxos
                    .iter()
                    .map(|s| parse_utxo_outpoint(s))
                    .collect::<Result<Vec<_>, WalletCliCommandError<N>>>(
                )?;

                let ComposedTransaction { hex, fees } = self
                    .non_empty_wallet()
                    .await?
                    .compose_transaction(input_utxos, outputs, None, only_transaction)
                    .await?;
                let mut output = format!("The hex encoded transaction is:\n{hex}\n");

                format_fees(&mut output, &fees);

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::AbandonTransaction { transaction_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet.abandon_transaction(selected_account, transaction_id.take()).await?;
                Ok(ConsoleCommand::Print(
                    "The transaction was marked as abandoned successfully".to_owned(),
                ))
            }

            WalletCommand::IssueNewToken {
                token_ticker,
                number_of_decimals,
                metadata_uri,
                destination_address,
                token_supply,
                is_freezable,
            } => {
                let token_supply = parse_token_supply(&token_supply, number_of_decimals)?;

                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_token = wallet
                    .issue_new_token(
                        selected_account,
                        destination_address,
                        TokenMetadata {
                            token_ticker: token_ticker.into(),
                            number_of_decimals,
                            metadata_uri: metadata_uri.into(),
                            token_supply,
                            is_freezable: is_freezable.to_bool(),
                        },
                        self.config,
                    )
                    .await?;

                Ok(ConsoleCommand::Print(format!(
                    "A new token has been issued with ID: {} in tx: {}",
                    new_token.token_id,
                    id_to_hex_string(*new_token.tx_id.as_hash())
                )))
            }

            WalletCommand::IssueNewNft {
                destination_address,
                media_hash,
                name,
                description,
                ticker,
                creator,
                icon_uri,
                media_uri,
                additional_metadata_uri,
            } => {
                let metadata = NftMetadata {
                    creator,
                    name: name.into(),
                    description: description.into(),
                    ticker,
                    icon_uri: icon_uri.map(Into::into),
                    additional_metadata_uri: additional_metadata_uri.map(Into::into),
                    media_uri: media_uri.map(Into::into),
                    media_hash,
                };

                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_token = wallet
                    .issue_new_nft(selected_account, destination_address, metadata, self.config)
                    .await?;

                Ok(ConsoleCommand::Print(format!(
                    "A new NFT has been issued with ID: {} in tx: {}",
                    new_token.token_id,
                    id_to_hex_string(*new_token.tx_id.as_hash())
                )))
            }

            WalletCommand::MintTokens {
                token_id,
                address,
                amount,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .mint_tokens(selected_account, token_id, address, amount, self.config)
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::UnmintTokens { token_id, amount } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx =
                    wallet.unmint_tokens(selected_account, token_id, amount, self.config).await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::LockTokenSupply { token_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx =
                    wallet.lock_token_supply(selected_account, token_id, self.config).await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::FreezeToken {
                token_id,
                is_unfreezable,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .freeze_token(
                        selected_account,
                        token_id,
                        is_unfreezable.to_bool(),
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::UnfreezeToken { token_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet.unfreeze_token(selected_account, token_id, self.config).await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::ChangeTokenAuthority { token_id, address } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .change_token_authority(selected_account, token_id, address, self.config)
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::ChangeTokenMetadataUri {
                token_id,
                metadata_uri,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .change_token_metadata_uri(
                        selected_account,
                        token_id,
                        metadata_uri,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::Rescan => {
                self.non_empty_wallet().await?.rescan().await?;
                Ok(ConsoleCommand::Print(
                    "Successfully rescanned the blockchain".to_owned(),
                ))
            }

            WalletCommand::SyncWallet => {
                self.non_empty_wallet().await?.sync().await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::GetBalance {
                utxo_states,
                with_locked,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let (coins, tokens) = wallet
                    .get_balance(
                        selected_account,
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await?
                    .into_coins_and_tokens();

                let coins = coins.decimal();
                let mut output = format!("Coins amount: {coins}\n");

                for (token_id, amount) in tokens {
                    let amount = amount.decimal();
                    writeln!(&mut output, "Token: {token_id} amount: {amount}")
                        .expect("Writing to a memory buffer should not fail");
                }
                output.pop();

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::ListUtxo {
                utxo_type,
                utxo_states,
                with_locked,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let utxos = wallet
                    .get_utxos(
                        selected_account,
                        utxo_type.to_wallet_types(),
                        CliUtxoState::to_wallet_states(utxo_states),
                        with_locked.to_wallet_type(),
                    )
                    .await?;
                Ok(ConsoleCommand::Print(
                    serde_json::to_string(&utxos).expect("ok"),
                ))
            }

            WalletCommand::ListPendingTransactions => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let utxos = wallet.list_pending_transactions(selected_account).await?;
                Ok(ConsoleCommand::PaginatedPrint {
                    header: "Pending Transactions".to_owned(),
                    body: format!("{utxos:#?}"),
                })
            }

            WalletCommand::ListMainchainTransactions { address, limit } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let txs =
                    wallet.list_transactions_by_address(selected_account, address, limit).await?;

                let table = {
                    let mut table = prettytable::Table::new();
                    table.set_titles(prettytable::row!["Id", "BlockHeight", "BlockTimestamp",]);

                    table.extend(txs.into_iter().map(|info| {
                        prettytable::row![
                            id_to_hex_string(*info.id.as_hash()),
                            info.height,
                            info.timestamp
                        ]
                    }));

                    table
                };

                Ok(ConsoleCommand::PaginatedPrint {
                    header: String::new(),
                    body: table.to_string(),
                })
            }

            WalletCommand::GetTransaction { transaction_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let tx = wallet
                    .get_transaction(selected_account, transaction_id.take())
                    .await
                    .map(|tx| serde_json::to_string(&tx).expect("ok"))?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawTransaction { transaction_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let tx =
                    wallet.get_raw_transaction(selected_account, transaction_id.take()).await?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::GetRawSignedTransaction { transaction_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let tx = wallet
                    .get_raw_signed_transaction(selected_account, transaction_id.take())
                    .await?;

                Ok(ConsoleCommand::Print(tx))
            }

            WalletCommand::SendToAddress {
                address,
                amount,
                utxos,
            } => {
                let input_utxos: Vec<UtxoOutPoint> = utxos
                    .iter()
                    .map(|s| parse_utxo_outpoint(s))
                    .collect::<Result<Vec<_>, WalletCliCommandError<N>>>(
                )?;
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .send_coins(selected_account, address, amount, input_utxos, self.config)
                    .await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::SweepFromAddress {
                destination_address,
                addresses,
                all,
            } => {
                // Clap should already prevent this
                ensure!(
                    all && addresses.is_empty() || !all && !addresses.is_empty(),
                    WalletCliCommandError::<N>::InvalidInput(
                        "Either set `--all` to sweep all addresses, or provide specific addresses — not both".to_owned()
                    )
                );
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet
                    .sweep_addresses(
                        selected_account,
                        destination_address,
                        addresses,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::SweepFromDelegation {
                destination_address,
                delegation_id,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet
                    .sweep_delegation(
                        selected_account,
                        destination_address,
                        delegation_id,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::CreateTxFromColdInput {
                address,
                amount,
                utxo,
                change_address,
            } => {
                let selected_input = parse_utxo_outpoint(&utxo)?;
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let ComposedTransaction { hex, fees } = wallet
                    .transaction_from_cold_input(
                        selected_account,
                        address,
                        amount,
                        selected_input,
                        change_address,
                        self.config,
                    )
                    .await?;

                let tx =
                    HexEncoded::<PartiallySignedTransaction>::from_str(&hex).expect("ok").take();

                let summary = tx.tx().text_summary(chain_config);

                let qr_code_string = (!self.no_qr)
                    .then(|| {
                        let qr_code = qrcode_or_error_string(&hex);
                        format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                    })
                    .unwrap_or_default();

                let mut output_str = format!(
                    "Send transaction created. \
                    Pass the following string into the cold wallet with private key to sign:\n\n{hex}\
                    {qr_code_string}\n\n{summary}\n"
                );
                format_fees(&mut output_str, &fees);

                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::InspectTransaction { transaction } => {
                let RpcInspectTransaction {
                    tx,
                    stats:
                        RpcSignatureStats {
                            num_inputs,
                            total_signatures,
                            validated_signatures,
                        },
                    fees,
                } = self.non_empty_wallet().await?.transaction_inspect(transaction).await?;

                let summary = tx.take().text_summary(chain_config);
                let mut output_str = format!("{summary}\n");
                if let Some(RpcValidatedSignatures {
                    num_valid_signatures,
                    num_invalid_signatures,
                    signature_statuses,
                }) = validated_signatures
                {
                    let missing_signatures = num_inputs - total_signatures;
                    writeln!(
                        output_str,
                        "Number of inputs: {num_inputs}\n\
                        Total signatures: {total_signatures}\n\
                        Valid signatures: {num_valid_signatures}\n\
                        Invalid signatures: {num_invalid_signatures}\n\
                        Missing signatures: {missing_signatures}\n"
                    )
                    .expect("Writing to a memory buffer should not fail");
                    let sig_statuses = signature_statuses
                        .iter()
                        .enumerate()
                        .map(format_signature_status)
                        .join("\n");
                    writeln!(output_str, "All signature statuses:\n{sig_statuses}\n")
                        .expect("Writing to a memory buffer should not fail");
                } else {
                    let missing_signatures = num_inputs - total_signatures;
                    writeln!(
                        output_str,
                        "Number of inputs: {num_inputs}\n\
                        Total signatures: {total_signatures}\n\
                        Missing signatures: {missing_signatures}\n
                        The signatures could not be verified because the UTXOs were spend or not found\n"
                    )
                    .expect("Writing to a memory buffer should not fail");
                }

                if let Some(fees) = fees {
                    format_fees(&mut output_str, &fees);
                } else {
                    writeln!(output_str, "Could not calculate fees")
                        .expect("Writing to a memory buffer should not fail");
                }

                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::SendTokensToAddress {
                token_id,
                address,
                amount,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .send_tokens(selected_account, token_id, address, amount, self.config)
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::MakeTxToSendTokensToAddressWithIntent {
                token_id,
                address,
                amount,
                intent,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let (signed_tx, signed_intent) = wallet
                    .make_tx_for_sending_tokens_with_intent(
                        selected_account,
                        token_id,
                        address,
                        amount,
                        intent,
                        self.config,
                    )
                    .await?;
                let tx_id = signed_tx.as_ref().transaction().get_id();

                let output = format!(
                    concat!(
                        "The hex encoded transaction is:\n{}\n\n",
                        "The transaction id is:\n{:x}\n\n",
                        "The hex encoded signed transaction intent is:\n{}\n"
                    ),
                    signed_tx, tx_id, signed_intent
                );

                Ok(ConsoleCommand::Print(output))
            }

            WalletCommand::MakeTxToSendTokensFromMultisigAddress {
                from_address,
                fee_change_address,
                outputs,
            } => {
                let outputs: Vec<GenericTokenTransfer> = outputs
                    .into_iter()
                    .map(|input| parse_generic_token_transfer(&input, chain_config))
                    .collect::<Result<Vec<_>, WalletCliCommandError<N>>>()?;

                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result = wallet
                    .make_tx_to_send_tokens_from_multisig_address(
                        selected_account,
                        from_address,
                        fee_change_address,
                        outputs,
                        self.config,
                    )
                    .await?;

                let tx = result.transaction.as_ref();

                let summary = tx.tx().text_summary(chain_config);

                let is_fully_signed = tx.all_signatures_available()
                    && result
                        .current_signatures
                        .iter()
                        .all(|s| *s == RpcSignatureStatus::FullySigned);

                let mut output_str = if is_fully_signed {
                    // Note: we can only get here if this wallet owns all keys of the multisig (including the case when
                    // it's a 1-of-1 multisig).

                    let signed_tx = tx.clone().into_signed_tx().expect("already checked");
                    let result_hex: HexEncoded<SignedTransaction> = signed_tx.into();

                    format!(
                        "The transaction has been fully signed and is ready to be broadcast to network. \
                        You can use the command `node-submit-transaction` in a wallet connected to the internet (this one or elsewhere). \
                        Pass the following data to the wallet to broadcast:\n\n{result_hex}\n\n{summary}"
                    )
                } else {
                    let current_sigs = result
                        .current_signatures
                        .iter()
                        .enumerate()
                        .map(format_signature_status)
                        .join(", ");

                    format!(
                        "Not all transaction inputs have been signed. This wallet does not have all the keys for that.\n\
                        The current signature states are:\n{current_sigs}.\n\
                        Pass the following string into the wallet that has appropriate keys for the inputs to sign what is left:\n\n\
                        {transaction}\n\n{summary}",
                        transaction = result.transaction
                    )
                };

                format_fees(&mut output_str, &result.fees);

                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::CreateDelegation { owner, pool_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let delegation_id = wallet
                    .create_delegation(selected_account, owner, pool_id, self.config)
                    .await?
                    .delegation_id;

                Ok(ConsoleCommand::Print(format!(
                    "Success, the creation of delegation transaction was broadcast to the network. Delegation id: {}",
                    delegation_id
                )))
            }

            WalletCommand::DelegateStaking {
                amount,
                delegation_id,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet
                    .delegate_staking(selected_account, amount, delegation_id, self.config)
                    .await?;

                Ok(ConsoleCommand::Print(
                    "Success, the delegation staking transaction was broadcast to the network"
                        .to_owned(),
                ))
            }

            WalletCommand::WithdrawFromDelegation {
                address,
                amount,
                delegation_id,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                wallet
                    .withdraw_from_delegation(
                        selected_account,
                        address,
                        amount,
                        delegation_id,
                        self.config,
                    )
                    .await?;
                Ok(ConsoleCommand::Print(
                    "Success. The transaction was broadcast to the network".to_owned(),
                ))
            }

            WalletCommand::CreateStakePool {
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
                staker_address,
                vrf_public_key,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .create_stake_pool(
                        selected_account,
                        amount,
                        cost_per_block,
                        margin_ratio_per_thousand,
                        decommission_address,
                        staker_address,
                        vrf_public_key,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::DecommissionStakePool {
                pool_id,
                output_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .decommission_stake_pool(
                        selected_account,
                        pool_id,
                        Some(output_address),
                        self.config,
                    )
                    .await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::DecommissionStakePoolRequest {
                pool_id,
                output_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result_hex = wallet
                    .decommission_stake_pool_request(
                        selected_account,
                        pool_id,
                        Some(output_address),
                        self.config,
                    )
                    .await?;

                let qr_code_string = (!self.no_qr)
                    .then(|| {
                        let qr_code = qrcode_or_error_string(&result_hex.to_string());
                        format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                    })
                    .unwrap_or_default();

                let output_str = format!(
                    "Decommission transaction created. \
                    Pass the following string into the wallet with private key to sign:\n\n{result_hex}\
                    {qr_code_string}"
                );
                Ok(ConsoleCommand::Print(output_str))
            }

            WalletCommand::DepositData { hex_data } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet.deposit_data(selected_account, hex_data, self.config).await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }

            WalletCommand::NodeVersion => {
                let version = self.wallet().await?.node_version().await?;
                Ok(ConsoleCommand::Print(version.version))
            }

            WalletCommand::ListPools => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let pool_ids: Vec<_> = wallet
                    .list_staking_pools(selected_account)
                    .await?
                    .into_iter()
                    .map(format_pool_info)
                    .collect();
                Ok(ConsoleCommand::Print(format!("{}\n", pool_ids.join("\n"))))
            }

            WalletCommand::ListOwnedPoolsForDecommission => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let pool_ids: Vec<_> = wallet
                    .list_pools_for_decommission(selected_account)
                    .await?
                    .into_iter()
                    .map(format_pool_info)
                    .collect();
                Ok(ConsoleCommand::Print(format!("{}\n", pool_ids.join("\n"))))
            }

            WalletCommand::ListDelegationIds => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let delegations: Vec<_> = wallet
                    .list_delegation_ids(selected_account)
                    .await?
                    .into_iter()
                    .map(|info| {
                        format_delegation_info(
                            info.delegation_id.to_string(),
                            info.balance.decimal().to_string(),
                        )
                    })
                    .collect();
                Ok(ConsoleCommand::Print(delegations.join("\n").to_string()))
            }

            WalletCommand::ListCreatedBlocksIds => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let mut block_ids = wallet.list_created_blocks_ids(selected_account).await?;
                block_ids.sort_by_key(|x| x.height);
                let result = block_ids
                    .into_iter()
                    .map(|block_info| {
                        let id = id_to_hex_string(*block_info.id.as_hash());
                        let h = block_info.height.into_int();
                        let pool_id = block_info.pool_id;
                        format!("({h}, {id}, {pool_id})")
                    })
                    .join("\n");
                Ok(ConsoleCommand::Print(result))
            }

            WalletCommand::NodeShutdown => {
                self.wallet().await?.node_shutdown().await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::NodeEnableNetworking { enable } => {
                self.wallet().await?.node_enable_networking(enable.is_enable()).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::Connect { address } => {
                self.wallet().await?.connect_to_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Disconnect { peer_id } => {
                self.wallet().await?.disconnect_peer(peer_id).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::ListBanned => {
                let list = self.wallet().await?.list_banned().await?;

                let msg = list
                    .iter()
                    .map(|(addr, banned_until)| format!("{addr} (banned until {banned_until})"))
                    .join("\n");

                Ok(ConsoleCommand::Print(msg))
            }
            WalletCommand::Ban { address, duration } => {
                self.wallet().await?.ban_address(address, duration).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::Unban { address } => {
                self.wallet().await?.unban_address(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::ListDiscouraged => {
                let list = self.wallet().await?.list_discouraged().await?;

                let msg = list
                    .iter()
                    .map(|(addr, discouraged_until)| {
                        format!("{addr} (discouraged until {discouraged_until})")
                    })
                    .join("\n");

                Ok(ConsoleCommand::Print(msg))
            }
            WalletCommand::Undiscourage { address } => {
                self.wallet().await?.undiscourage_address(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }

            WalletCommand::PeerCount => {
                let peer_count = self.wallet().await?.peer_count().await?;
                Ok(ConsoleCommand::Print(peer_count.to_string()))
            }
            WalletCommand::ConnectedPeers => {
                let peers = self.wallet().await?.connected_peers().await?;
                Ok(ConsoleCommand::Print(format!("{peers:#?}")))
            }
            WalletCommand::ConnectedPeersJson => {
                let peers = self.wallet().await?.connected_peers().await?;
                let peers_json = serde_json::to_string(&peers)?;
                Ok(ConsoleCommand::Print(peers_json))
            }
            WalletCommand::ReservedPeers => {
                let peers = self.wallet().await?.reserved_peers().await?;
                Ok(ConsoleCommand::Print(format!("{peers:#?}")))
            }
            WalletCommand::AddReservedPeer { address } => {
                self.wallet().await?.add_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::RemoveReservedPeer { address } => {
                self.wallet().await?.remove_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
        }
    }

    pub async fn handle_manageable_wallet_command<N: NodeInterface>(
        &mut self,
        chain_config: &ChainConfig,
        command: ManageableWalletCommand,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        match command {
            ManageableWalletCommand::WalletCommands(command) => {
                self.handle_wallet_command(chain_config, command).await
            }
            ManageableWalletCommand::ManagementCommands(command) => {
                self.handle_wallet_management_command(command).await
            }
        }
    }
}

fn format_signature_status((idx, status): (usize, &RpcSignatureStatus)) -> String {
    let status = match status {
        RpcSignatureStatus::FullySigned => "FullySigned".to_owned(),
        RpcSignatureStatus::NotSigned => "NotSigned".to_owned(),
        RpcSignatureStatus::InvalidSignature => "InvalidSignature".to_owned(),
        RpcSignatureStatus::UnknownSignature => "UnknownSignature".to_owned(),
        RpcSignatureStatus::PartialMultisig { required_signatures, num_signatures } => format!("PartialMultisig having {num_signatures} out of {required_signatures} required signatures"),
    };

    format!("Signature for input {idx}: {status}")
}

fn format_fees(output: &mut String, fees: &Balances) {
    let coins = fees.coins().decimal();
    let tokens = fees.tokens();
    writeln!(
        output,
        "Fees that will be paid by the transaction:\nCoins amount: {coins}\n"
    )
    .expect("Writing to a memory buffer should not fail");

    for (token_id, amount) in tokens {
        let amount = amount.decimal();
        writeln!(output, "Token: {token_id} amount: {amount}")
            .expect("Writing to a memory buffer should not fail");
    }
    output.pop();
}

fn id_to_hex_string(id: H256) -> String {
    let hex_string = format!("{:?}", id);
    hex_string.strip_prefix("0x").unwrap_or(&hex_string).to_string()
}

/// This is a helper function used to ensure that failing to output a QR code will only display an error message instead of completely failing the command
fn qrcode_or_error_string(str_data: &str) -> String {
    let make_error_str = |e: QrCodeError| format!("<<Failed to generate QR Code: {e}>>");
    let qr_code_result = utils::qrcode::qrcode_from_str(str_data);
    qr_code_result.map_or_else(make_error_str, |qr| {
        qr.encode_to_console_string_with_defaults(1)
    })
}

async fn wallet_and_selected_acc<E, W, N>(
    wallet: &mut WalletWithState<W>,
) -> Result<(&W, U31), WalletCliCommandError<N>>
where
    W: WalletInterface<Error = E> + Send + Sync + 'static,
    N: NodeInterface,
{
    wallet.get_wallet_with_acc().await
}
