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

use std::{collections::BTreeMap, fmt::Write, str::FromStr};

use bigdecimal::BigDecimal;
use itertools::Itertools;

use chainstate::ChainInfo;
use chainstate::rpc::RpcOutputValueOut;
use common::{
    address::{Address, RpcAddress},
    chain::{
        ChainConfig, Destination, RpcCurrency, SignedTransaction, block::timestamp::BlockTimestamp,
        config::checkpoints_data::print_block_heights_ids_as_checkpoints_data, htlc::HtlcSecret,
        tokens::TokenId, transaction::Transaction,
    },
    primitives::{BlockHeight, H256, Id, Idable as _},
    text_summary::TextSummary,
};
use crypto::key::hdkd::u31::U31;
use logging::log;
use mempool::tx_options::TxOptionsOverrides;
use node_comm::node_traits::NodeInterface;
use p2p_types::socket_address::SocketAddress;
use rpc::types::RpcHexString;
use serialization::{hex::HexEncode, hex_encoded::HexEncoded};
use utils::{
    app_version_with_git_info, ensure,
    qrcode::{QrCode, QrCodeError},
    sorted::Sorted as _,
};
use wallet_controller::{ConnectedPeer, types::WalletExtraInfo};
use wallet_rpc_client::wallet_rpc_traits::{PartialOrSignedTx, WalletInterface};
#[cfg(any(feature = "trezor", feature = "ledger"))]
use wallet_rpc_lib::types::HardwareWalletType;
use wallet_rpc_lib::types::{
    Balances, ComposedTransaction, ControllerConfig, MnemonicInfo, NewOrderTransaction,
    NewSubmittedTransaction, NftMetadata, RpcHashedTimelockContract, RpcInspectTransaction,
    RpcNewTransaction, RpcPreparedTransaction, RpcSignatureStats, RpcSignatureStatus,
    RpcStandaloneAddressDetails, RpcValidatedSignatures, TokenMetadata,
};
use wallet_types::partially_signed_transaction::PartiallySignedTransaction;

#[cfg(feature = "trezor")]
use crate::{CreateWalletDeviceSelectMenu, OpenWalletDeviceSelectMenu};

use self::local_state::WalletWithState;

use super::{
    ColdWalletCommand, ConsoleCommand, WalletCommand,
    helper_types::{
        CliForceReduceLookaheadSize, CliUtxoState, format_active_order_info,
        format_delegation_info, format_own_order_info, format_pool_info,
    },
};
use crate::{
    AccountGroupSubCommand, AddressGroupSubCommand, CliPublicKeyFormat, DataGroupSubCommand,
    DelegationGroupSubCommand, HtlcGroupSubCommand, ManageableWalletCommand, NftGroupSubCommand,
    OpenWalletSubCommand, OrderGroupSubCommand, StakingGroupSubCommand, StandaloneGroupSubCommand,
    TokenGroupSubCommand, TransactionGroupSubCommand, WalletGroupSubCommand,
    WalletManagementCommand,
    errors::WalletCliCommandError,
    helper_types::{
        CliCurrency, active_order_infos_header, format_token_name, token_ticker_from_rpc_token_info,
    },
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

    fn new_tx_command_status_text(new_tx: RpcNewTransaction, chain_config: &ChainConfig) -> String {
        if new_tx.broadcasted {
            let mut summary = new_tx.tx.take().transaction().text_summary(chain_config);
            format_fees(&mut summary, &new_tx.fees);

            format!(
                "{summary}\nThe transaction was submitted successfully with ID:\n{}",
                id_to_hex_string(*new_tx.tx_id.as_hash())
            )
        } else {
            format_tx_to_be_broadcasted(new_tx.tx, &new_tx.fees, chain_config)
        }
    }

    pub fn new_tx_command(new_tx: RpcNewTransaction, chain_config: &ChainConfig) -> ConsoleCommand {
        ConsoleCommand::Print(Self::new_tx_command_status_text(new_tx, chain_config))
    }

    pub fn prepared_tx_command(
        prepared_tx: RpcPreparedTransaction,
        chain_config: &ChainConfig,
    ) -> ConsoleCommand {
        let RpcPreparedTransaction { tx_id, tx, fees } = prepared_tx;
        let new_tx = RpcNewTransaction {
            tx_id,
            tx,
            fees,
            broadcasted: false,
        };

        Self::new_tx_command(new_tx, chain_config)
    }

    pub fn new_order_tx_command<N: NodeInterface>(
        new_tx: NewOrderTransaction,
        chain_config: &ChainConfig,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>> {
        let (order_id, new_tx) = new_tx.into_order_id_and_new_tx();
        let order_id = order_id
            .into_address(chain_config)
            .map_err(|_| WalletCliCommandError::InvalidAddressInNewlyCreatedTransaction)?;
        let status_text = Self::new_tx_command_status_text(new_tx, chain_config);
        let status_text = format!("New order id: {order_id}\n\n{status_text}");

        Ok(ConsoleCommand::Print(status_text))
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
                        #[cfg(feature = "trezor")]
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
                        #[cfg(feature = "trezor")]
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
                        #[cfg(feature = "trezor")]
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
                        #[cfg(feature = "ledger")]
                        OpenWalletSubCommand::Ledger {
                            wallet_path,
                            encryption_password,
                        } => (
                            wallet_path,
                            encryption_password,
                            false,
                            Some(HardwareWalletType::Ledger),
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
                        #[cfg(feature = "trezor")]
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
                let wallet_description = match info.extra_info {
                    WalletExtraInfo::SoftwareWallet => "This is a software wallet".to_owned(),
                    #[cfg(feature = "trezor")]
                    WalletExtraInfo::TrezorWallet {
                        device_name,
                        device_id,
                        firmware_version,
                    } => {
                        format!(
                            "This is a Trezor wallet; device name: {}, device id: {}, firmware version: {}",
                            device_name, device_id, firmware_version
                        )
                    }
                    #[cfg(feature = "ledger")]
                    WalletExtraInfo::LedgerWallet { app_version, model } => format!(
                        "This is a Ledger wallet; model: {model}, running app version {}",
                        app_version
                    ),
                };
                let account_names = info
                    .account_names
                    .into_iter()
                    .enumerate()
                    .map(|(idx, name)| {
                        let name = name.map_or("None".into(), |name| format!("\"{name}\""));
                        format!("Account index: {idx}, Name: {name}")
                    })
                    .join("\n");

                Ok(ConsoleCommand::Print(format!(
                    "{wallet_description}\nWallet Accounts:\n{account_names}"
                )))
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
                    format!(
                        "The seed phrase has been deleted, you can store it if you haven't done so yet: \"{}\"{passphrase}",
                        phrase.seed_phrase.join(" ")
                    )
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
                    Some(CliForceReduceLookaheadSize::IKnowWhatIAmDoing) => true,
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

            ColdWalletCommand::AccountExtendedPublicKey => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let key = wallet.get_account_extended_public_key(selected_account).await?;
                let hex_public_key = key.public_key.to_string();
                let hex_chain_code = key.chain_code.to_string();

                let extended_public_key = format!("{hex_public_key}{hex_chain_code}");
                let qr_code = if !self.no_qr {
                    let qr_code = qrcode_or_error_string(&extended_public_key);
                    format!("\nOr contained in the QR code:\n{qr_code}")
                } else {
                    String::new()
                };

                Ok(ConsoleCommand::Print(format!(
                    "The account extended public key is: {extended_public_key}{qr_code}"
                )))
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
                    // TODO: it'd be nice to print token tickers here too (as in GetBalance),
                    // when the wallet is in the hot mode.
                    writeln!(&mut output, "Token: {token_id}, amount: {amount}")
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

                        let qr_code_string = if self.no_qr {
                            String::new()
                        } else {
                            let qr_code = qrcode_or_error_string(&result_hex.to_string());
                            format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                        };

                        format!(
                            "The transaction has been fully signed and is ready to be broadcast to network. \
                             You can use the command `node-submit-transaction` in a wallet connected to the internet (this one or elsewhere). \
                             Pass the following data to the wallet to broadcast:\n\n{result_hex}\
                             {qr_code_string}\n\n{summary}"
                        )
                    }
                    PartialOrSignedTx::Partial(partially_signed_tx) => {
                        let result_hex: HexEncoded<PartiallySignedTransaction> =
                            partially_signed_tx.into();

                        let qr_code_string = if self.no_qr {
                            String::new()
                        } else {
                            let qr_code = qrcode_or_error_string(&result_hex.to_string());
                            format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                        };

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

                let qr_code_string = if self.no_qr {
                    String::new()
                } else {
                    let qr_code = qrcode_or_error_string(&result);
                    format!(
                        "\n\nThe following qr code also contains the signature for easy transport:\n{qr_code}"
                    )
                };

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex-encoded signature is\n\n{result}{qr_code_string}",
                )))
            }

            ColdWalletCommand::SignChallege {
                message: challenge,
                address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let result = wallet.sign_challenge(selected_account, challenge, address).await?;

                let qr_code_string = if self.no_qr {
                    String::new()
                } else {
                    let qr_code = qrcode_or_error_string(&result);
                    format!(
                        "\n\nThe following qr code also contains the signature for easy transport:\n{qr_code}"
                    )
                };

                Ok(ConsoleCommand::Print(format!(
                    "The generated hex-encoded signature is\n\n{result}{qr_code_string}",
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

            ColdWalletCommand::Version => Ok(ConsoleCommand::Print(
                app_version_with_git_info!().to_pretty_string(),
            )),
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
            WalletCommand::Wallet { command } => {
                let management = match command {
                    WalletGroupSubCommand::Create { wallet } => {
                        WalletManagementCommand::CreateWallet { wallet }
                    }
                    WalletGroupSubCommand::Recover { wallet } => {
                        WalletManagementCommand::RecoverWallet { wallet }
                    }
                    WalletGroupSubCommand::Open { wallet } => {
                        WalletManagementCommand::OpenWallet { wallet }
                    }
                    WalletGroupSubCommand::Close => WalletManagementCommand::CloseWallet,
                };
                self.handle_wallet_management_command(management).await
            }
            // Keep this or-pattern in sync with `is_nested_wallet_command` and the
            // translation arms in `normalize_nested_wallet_command`: a group added here
            // needs a variant in the predicate, a translation arm, and a LEGACY_ALIASES
            // entry so the coexistence and translation tests pin all three sites.
            command @ (WalletCommand::Account { .. }
            | WalletCommand::Address { .. }
            | WalletCommand::Send { .. }
            | WalletCommand::Data { .. }
            | WalletCommand::Staking { .. }
            | WalletCommand::Delegation { .. }
            | WalletCommand::Token { .. }
            | WalletCommand::Order { .. }
            | WalletCommand::Htlc { .. }
            | WalletCommand::Transaction { .. }) => {
                // Nested groups translate to their flat equivalents. The recursive call
                // is boxed to keep the future size finite; translation always produces a
                // flat command, so the recursion never goes deeper than one level.
                let normalized = normalize_nested_wallet_command(command);
                // Translation must terminate: a nested command fed back into this handler
                // would recurse unboundedly through the boxed call.
                assert!(
                    !is_nested_wallet_command(&normalized),
                    "translation must produce a flat command, otherwise this recursion is unbounded"
                );
                Box::pin(self.handle_wallet_command(chain_config, normalized)).await
            }

            WalletCommand::ConfigBroadcast { broadcast } => {
                self.config.broadcast_to_mempool = broadcast.to_bool();
                Ok(ConsoleCommand::Print(format!(
                    "Broadcast to Mempool set to: {broadcast:?}"
                )))
            }

            WalletCommand::ChainstateInfo => {
                let info = self.wallet().await?.chainstate_info().await?;
                Ok(ConsoleCommand::Print(format_chainstate_info(&info)))
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

            WalletCommand::GetBlock { id } => {
                let block = self.wallet().await?.node_block(id).await?;
                match block {
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
                Ok(ConsoleCommand::Print(format_staking_timestamps(
                    &timestamp_map,
                )))
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
                    format!(
                        "Success. The following new multisig address has been added to the account\n{multisig_address}"
                    )
                } else {
                    format!(
                        "Success. The following new multisig address has been added to the account\n{multisig_address}\nRescanning the blockchain to detect balance in added new addresses"
                    )
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
                let outputs = outputs
                    .into_iter()
                    .map(|output| output.to_coin_tx_output(chain_config))
                    .collect::<Result<Vec<_>, _>>()?;

                let utxos = utxos.into_iter().map(Into::into).collect();

                let ComposedTransaction { hex, fees } = self
                    .non_empty_wallet()
                    .await?
                    .compose_transaction(utxos, outputs, None, only_transaction)
                    .await?;
                let mut output = format!("The hex-encoded transaction is:\n{hex}\n");

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
                authority_address,
                token_supply,
                is_freezable,
            } => {
                let token_supply = token_supply.to_fully_parsed(number_of_decimals)?;

                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_token = wallet
                    .issue_new_token(
                        selected_account,
                        authority_address,
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

                let result = if new_token.broadcasted {
                    format!(
                        "A new token has been issued with ID: {} in tx: {}",
                        new_token.token_id,
                        id_to_hex_string(*new_token.tx_id.as_hash())
                    )
                } else {
                    format_tx_to_be_broadcasted(new_token.tx, &new_token.fees, chain_config)
                };

                Ok(ConsoleCommand::Print(result))
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

                let result = if new_token.broadcasted {
                    format!(
                        "A new NFT has been issued with ID: {} in tx: {}",
                        new_token.token_id,
                        id_to_hex_string(*new_token.tx_id.as_hash())
                    )
                } else {
                    format_tx_to_be_broadcasted(new_token.tx, &new_token.fees, chain_config)
                };

                Ok(ConsoleCommand::Print(result))
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

                let token_ids_str_vec =
                    tokens.keys().map(|token_id| token_id.as_str().to_owned()).collect_vec();

                let token_infos = wallet
                    .node_get_tokens_info(token_ids_str_vec)
                    .await?
                    .into_iter()
                    .map(|info| (info.token_id(), info))
                    .collect();

                let coins = coins.decimal();
                let mut output = format!("Coins amount: {coins}\n");

                for (token_id, amount) in tokens {
                    let token_name = format_token_name(&token_id, chain_config, &token_infos)?;
                    let amount = amount.decimal();
                    writeln!(&mut output, "Token: {token_name}, amount: {amount}")
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
                let transactions = wallet.list_pending_transactions(selected_account).await?;
                Ok(ConsoleCommand::PaginatedPrint {
                    header: "Pending transactions".to_owned(),
                    body: format_pending_transaction_ids(&transactions),
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
                let utxos = utxos.into_iter().map(Into::into).collect();
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .send_coins(selected_account, address, amount, utxos, self.config)
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
                        all,
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
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let ComposedTransaction { hex, fees } = wallet
                    .transaction_from_cold_input(
                        selected_account,
                        address,
                        amount,
                        utxo.into(),
                        change_address,
                        self.config,
                    )
                    .await?;

                let tx =
                    HexEncoded::<PartiallySignedTransaction>::from_str(&hex).expect("ok").take();

                let summary = tx.tx().text_summary(chain_config);

                let qr_code_string = if self.no_qr {
                    String::new()
                } else {
                    let qr_code = qrcode_or_error_string(&hex);
                    format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                };

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
                        "The hex-encoded transaction is:\n{}\n\n",
                        "The transaction id is:\n{:x}\n\n",
                        "The hex-encoded signed transaction intent is:\n{}\n"
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
                let outputs = outputs
                    .into_iter()
                    .map(|ouput| ouput.to_fully_parsed(chain_config))
                    .collect::<Result<Vec<_>, _>>()?;

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
                let new_delegation =
                    wallet.create_delegation(selected_account, owner, pool_id, self.config).await?;

                let result = if new_delegation.broadcasted {
                    format!(
                        "Success, the creation of delegation transaction was broadcast to the network. Delegation id: {} in tx: {}",
                        new_delegation.delegation_id,
                        id_to_hex_string(*new_delegation.tx_id.as_hash())
                    )
                } else {
                    format_tx_to_be_broadcasted(
                        new_delegation.tx,
                        &new_delegation.fees,
                        chain_config,
                    )
                };

                Ok(ConsoleCommand::Print(result))
            }

            WalletCommand::DelegateStaking {
                amount,
                delegation_id,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .delegate_staking(selected_account, amount, delegation_id, self.config)
                    .await?;

                let result = if new_tx.broadcasted {
                    "Success, the delegation staking transaction was broadcast to the network"
                        .to_owned()
                } else {
                    format_tx_to_be_broadcasted(new_tx.tx, &new_tx.fees, chain_config)
                };

                Ok(ConsoleCommand::Print(result))
            }

            WalletCommand::WithdrawFromDelegation {
                address,
                amount,
                delegation_id,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let new_tx = wallet
                    .withdraw_from_delegation(
                        selected_account,
                        address,
                        amount,
                        delegation_id,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
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

                let qr_code_string = if self.no_qr {
                    String::new()
                } else {
                    let qr_code = qrcode_or_error_string(&result_hex.to_string());
                    format!("\n\nOr scan the Qr code with it:\n\n{qr_code}")
                };

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
                let pool_infos: Vec<_> = wallet
                    .list_staking_pools(selected_account)
                    .await?
                    .into_iter()
                    .map(format_pool_info)
                    .collect();
                Ok(ConsoleCommand::Print(format!(
                    "{}\n",
                    pool_infos.join("\n")
                )))
            }

            WalletCommand::ListOwnedPoolsForDecommission => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;
                let pool_infos: Vec<_> = wallet
                    .list_pools_for_decommission(selected_account)
                    .await?
                    .into_iter()
                    .map(format_pool_info)
                    .collect();
                Ok(ConsoleCommand::Print(format!(
                    "{}\n",
                    pool_infos.join("\n")
                )))
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
                Ok(ConsoleCommand::Print(delegations.join("\n").clone()))
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
                Ok(ConsoleCommand::from(
                    crate::output::CommandOutput::with_payload(
                        peer_count.to_string(),
                        serde_json::json!({ "peer_count": peer_count }),
                    ),
                ))
            }
            WalletCommand::ConnectedPeers => {
                let peers = self.wallet().await?.connected_peers().await?;
                Ok(ConsoleCommand::Print(format_connected_peers(&peers)))
            }
            WalletCommand::ConnectedPeersJson => {
                let peers = self.wallet().await?.connected_peers().await?;
                let peers_json = serde_json::to_string(&peers)?;
                Ok(ConsoleCommand::Print(peers_json))
            }
            WalletCommand::ReservedPeers => {
                let peers = self.wallet().await?.reserved_peers().await?;
                Ok(ConsoleCommand::Print(format_reserved_peers(&peers)))
            }
            WalletCommand::AddReservedPeer { address } => {
                self.wallet().await?.add_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::RemoveReservedPeer { address } => {
                self.wallet().await?.remove_reserved_peer(address).await?;
                Ok(ConsoleCommand::Print("Success".to_owned()))
            }
            WalletCommand::CreateOrder {
                ask_currency,
                ask_amount,
                give_currency,
                give_amount,
                conclude_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let parse_token_id =
                    |currency: &CliCurrency| -> Result<_, WalletCliCommandError<N>> {
                        let parsed_currency = currency
                            .to_fully_parsed(chain_config)?
                            .to_rpc_currency(chain_config)?;
                        match parsed_currency {
                            RpcCurrency::Coin => Ok(None),
                            RpcCurrency::Token(token_id) => Ok(Some(token_id.into_string())),
                        }
                    };

                let ask_token_id = parse_token_id(&ask_currency)?;
                let give_token_id = parse_token_id(&give_currency)?;
                let new_tx = wallet
                    .create_order(
                        selected_account,
                        ask_token_id,
                        ask_amount,
                        give_token_id,
                        give_amount,
                        conclude_address,
                        self.config,
                    )
                    .await?;
                Ok(Self::new_order_tx_command(new_tx, chain_config)?)
            }
            WalletCommand::FillOrder {
                order_id,
                amount,
                output_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet
                    .fill_order(
                        selected_account,
                        order_id,
                        amount,
                        output_address,
                        self.config,
                    )
                    .await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }
            WalletCommand::FreezeOrder { order_id } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet.freeze_order(selected_account, order_id, self.config).await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }
            WalletCommand::ConcludeOrder {
                order_id,
                output_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet
                    .conclude_order(selected_account, order_id, output_address, self.config)
                    .await?;
                Ok(Self::new_tx_command(new_tx, chain_config))
            }
            WalletCommand::ListOwnOrders => self.list_own_orders(chain_config).await,
            WalletCommand::ListActiveOrders {
                ask_currency,
                give_currency,
            } => self.list_all_active_orders(chain_config, ask_currency, give_currency).await,

            WalletCommand::CreateHtlcTx {
                currency,
                amount,
                secret_hash,
                spend_address,
                refund_timelock,
                refund_address,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let token_id =
                    match currency.to_fully_parsed(chain_config)?.to_rpc_currency(chain_config)? {
                        RpcCurrency::Coin => Ok(None),
                        RpcCurrency::Token(token_id) => Ok(Some(token_id.into_string())),
                    }?;

                let htlc = RpcHashedTimelockContract {
                    secret_hash: RpcHexString::from_str(&secret_hash)?,
                    spend_address: RpcAddress::from_string(spend_address),
                    refund_address: RpcAddress::from_string(refund_address),
                    refund_timelock: refund_timelock.into(),
                };

                let prepared_tx = wallet
                    .create_htlc_transaction(selected_account, amount, token_id, htlc, self.config)
                    .await?;

                Ok(Self::prepared_tx_command(prepared_tx, chain_config))
            }

            WalletCommand::GenerateHtlcSecret => {
                let secret = HtlcSecret::new_from_rng(&mut randomness::make_true_rng());
                let secret_hash = secret.hash();

                Ok(ConsoleCommand::Print(format!(
                    "New HTLC secret: {}\nand its hash: {:x}",
                    hex::encode(secret.secret()),
                    secret_hash
                )))
            }

            WalletCommand::CalcHtlcSecretHash { secret } => {
                let secret = hex::decode(&secret)
                    .ok()
                    .and_then(|bytes| Some(HtlcSecret::new(bytes.try_into().ok()?)))
                    .ok_or(WalletCliCommandError::InvalidHtlcSecret)?;
                let secret_hash = secret.hash();

                Ok(ConsoleCommand::Print(format!(
                    "The hash of the provided secret is: {secret_hash:x}",
                )))
            }

            WalletCommand::SpendUtxo {
                utxo,
                address,
                htlc_secret,
            } => {
                let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

                let new_tx = wallet
                    .spend_utxo(
                        selected_account,
                        utxo.into(),
                        address,
                        htlc_secret,
                        self.config,
                    )
                    .await?;

                Ok(Self::new_tx_command(new_tx, chain_config))
            }
        }
    }

    async fn list_own_orders<N: NodeInterface>(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

        let order_infos = wallet.list_own_orders(selected_account).await?;
        let token_ids_str_vec = get_token_ids_from_order_infos_as_str(
            order_infos.iter().map(|info| (&info.initially_asked, &info.initially_given)),
        );

        let token_infos = wallet
            .node_get_tokens_info(token_ids_str_vec)
            .await?
            .into_iter()
            .map(|info| (info.token_id(), info))
            .collect();

        // Sort the orders, so that the newer ones appear later.
        let order_infos = order_infos.sorted_by(|info1, info2| {
            use std::cmp::Ordering;

            let ts1 = info1.existing_order_data.as_ref().map(|data| data.creation_timestamp);
            let ts2 = info2.existing_order_data.as_ref().map(|data| data.creation_timestamp);

            let ts_cmp_result = match (ts1, ts2) {
                (Some(ts1), Some(ts2)) => ts1.cmp(&ts2),
                // Note: the logic here is opposite to the normal comparison of Option's -
                // we want None to be bigger than Some, so that "unconfirmed" orders
                // appear later in the list.
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };

            // If the timestamps are equal, sort the orders by id in the bech32 encoding.
            ts_cmp_result.then_with(|| info1.order_id.cmp(&info2.order_id))
        });

        let order_infos = order_infos
            .iter()
            .map(|info| format_own_order_info(info, chain_config, &token_infos))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ConsoleCommand::Print(format!(
            "{}\n",
            order_infos.join("\n")
        )))
    }

    async fn list_all_active_orders<N: NodeInterface>(
        &mut self,
        chain_config: &ChainConfig,
        ask_currency: Option<CliCurrency>,
        give_currency: Option<CliCurrency>,
    ) -> Result<ConsoleCommand, WalletCliCommandError<N>>
    where
        WalletCliCommandError<N>: From<E>,
    {
        let (wallet, selected_account) = wallet_and_selected_acc(&mut self.wallet).await?;

        let parse_currency = |currency: CliCurrency| -> Result<_, WalletCliCommandError<N>> {
            Ok(currency.to_fully_parsed(chain_config)?.to_rpc_currency(chain_config)?)
        };

        let ask_currency = ask_currency.map(parse_currency).transpose()?;
        let give_currency = give_currency.map(parse_currency).transpose()?;

        let order_infos = wallet
            .list_all_active_orders(selected_account, ask_currency, give_currency)
            .await?;
        let (token_ids_map, token_infos) = {
            let token_ids_iter = get_token_ids_from_order_infos(
                order_infos.iter().map(|info| (&info.initially_asked, &info.initially_given)),
            );
            let token_ids_str_vec = token_ids_iter
                .clone()
                .map(|rpc_addr| rpc_addr.as_str().to_owned())
                .collect_vec();
            let token_ids_map = token_ids_iter
                .map(|rpc_addr| -> Result<_, WalletCliCommandError<N>> {
                    Ok((
                        rpc_addr.clone(),
                        rpc_addr
                            .decode_object(chain_config)
                            .map_err(WalletCliCommandError::TokenIdDecodingError)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let token_infos = wallet
                .node_get_tokens_info(token_ids_str_vec)
                .await?
                .into_iter()
                .map(|info| (info.token_id(), info))
                .collect::<BTreeMap<_, _>>();

            (token_ids_map, token_infos)
        };

        // Calculate give/ask price for each order. Note:
        // 1) The price is based on original amounts, which is valid for orders v1 but not for v0;
        // this is ok, because orders v0 will be deprecated soon.
        // 2) The `filter_map` call shouldn't filter anything out normally; if it does, then
        // the implementation of `node_get_tokens_info` has a bug.
        let order_infos_with_price = order_infos
            .into_iter()
            .filter_map(|info| {
                let get_decimals = |token_id_opt: Option<&TokenId>| {
                    if let Some(token_id) = token_id_opt {
                        if let Some(info) = token_infos.get(token_id) {
                            Some(info.token_number_of_decimals())
                        }
                        else {
                            log::error!(
                                "Token {token_id:x} is missing in the result of node_get_tokens_info"
                            );
                            None
                        }
                    } else {
                        Some(chain_config.coin_decimals())
                    }
                };

                let asked_token_id = info.initially_asked.token_id().map(|token_id| {
                    token_ids_map.get(token_id).expect("Token id is known to be present")
                });
                let given_token_id = info.initially_given.token_id().map(|token_id| {
                    token_ids_map.get(token_id).expect("Token id is known to be present")
                });
                let ask_currency_decimals = get_decimals(asked_token_id)?;
                let give_currency_decimals = get_decimals(given_token_id)?;

                let give_ask_price = BigDecimal::new(
                    info.initially_given.amount().amount().into_atoms().into(),
                    give_currency_decimals as i64,
                ) / BigDecimal::new(
                    info.initially_asked.amount().amount().into_atoms().into(),
                    ask_currency_decimals as i64,
                );
                let give_ask_price = give_ask_price.with_scale_round(
                    give_currency_decimals.into(),
                    bigdecimal::rounding::RoundingMode::Down,
                );

                Some((info, give_ask_price))
            })
            .collect_vec();

        // This will be used with order_infos_with_price, so we know that the token_infos map
        // contains all tokens that we may encounter here.
        let compare_currencies =
            |token1_id: Option<&RpcAddress<TokenId>>, token2_id: Option<&RpcAddress<TokenId>>| {
                use std::cmp::Ordering;

                let ticker_by_id = |token_id| {
                    token_ticker_from_rpc_token_info(
                        token_infos.get(token_id).expect("Token info is known to be present"),
                    )
                };

                match (token1_id, token2_id) {
                    (Some(token1_id_as_addr), Some(token2_id_as_addr)) => {
                        let token1_id = token_ids_map
                            .get(token1_id_as_addr)
                            .expect("Token id is known to be present");
                        let token2_id = token_ids_map
                            .get(token2_id_as_addr)
                            .expect("Token id is known to be present");

                        if token1_id == token2_id {
                            Ordering::Equal
                        } else {
                            let token1_ticker = ticker_by_id(token1_id);
                            let token2_ticker = ticker_by_id(token2_id);

                            // Compare the tickers first; if they are equal, compare the ids.
                            token1_ticker
                                .cmp(token2_ticker)
                                .then(token1_id_as_addr.cmp(token2_id_as_addr))
                        }
                    }
                    // The coin should come first, so it's "less" than tokens.
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => Ordering::Equal,
                }
            };

        let order_infos_with_give_ask_price = order_infos_with_price.sorted_by(
            |(order1_info, order1_price), (order2_info, order2_price)| {
                let order1_asked_token_id = order1_info.initially_asked.token_id();
                let order1_given_token_id = order1_info.initially_given.token_id();
                let order2_asked_token_id = order2_info.initially_asked.token_id();
                let order2_given_token_id = order2_info.initially_given.token_id();

                compare_currencies(order1_given_token_id, order2_given_token_id)
                    .then_with(|| compare_currencies(order1_asked_token_id, order2_asked_token_id))
                    .then_with(|| order2_price.cmp(order1_price))
                    // If the price is the same, sort by the order id.
                    .then_with(|| order1_info.order_id.cmp(&order2_info.order_id))
            },
        );

        let formatted_order_infos = order_infos_with_give_ask_price
            .iter()
            .map(|(info, give_ask_price)| {
                format_active_order_info(info, give_ask_price, chain_config, &token_infos)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ConsoleCommand::Print(format!(
            "{}\n{}\n",
            active_order_infos_header(),
            formatted_order_infos.join("\n")
        )))
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

/// Whether the command still carries a nested group that must be translated before
/// dispatch. Shared by the dispatch guard and the translation tests so both stay in
/// sync when new groups are added.
fn is_nested_wallet_command(command: &WalletCommand) -> bool {
    // Keep in sync with the dispatch or-pattern in `handle_wallet_command` and the
    // translation arms in `normalize_nested_wallet_command`; the LEGACY_ALIASES
    // coexistence test and the translation test pin the three sites together.
    matches!(
        command,
        WalletCommand::Wallet { .. }
            | WalletCommand::Account { .. }
            | WalletCommand::Address { .. }
            | WalletCommand::Send { .. }
            | WalletCommand::Data { .. }
            | WalletCommand::Staking { .. }
            | WalletCommand::Delegation { .. }
            | WalletCommand::Token { .. }
            | WalletCommand::Order { .. }
            | WalletCommand::Htlc { .. }
            | WalletCommand::Transaction { .. }
    )
}

/// Translate the nested command grammar (`account select`, `address qr`, `send`, ...)
/// into the flat commands that drive the implementation, so every command has exactly
/// one implementation regardless of how it was spelled. The `wallet` group is handled
/// at the dispatch site because it maps onto the wallet management commands.
fn normalize_nested_wallet_command(command: WalletCommand) -> WalletCommand {
    match command {
        WalletCommand::Account { command } => match command {
            AccountGroupSubCommand::Create { name } => WalletCommand::CreateNewAccount { name },
            AccountGroupSubCommand::Rename { name } => WalletCommand::RenameAccount { name },
            AccountGroupSubCommand::Select { account_index } => {
                WalletCommand::SelectAccount { account_index }
            }
            AccountGroupSubCommand::Utxos {
                utxo_type,
                with_locked,
                utxo_states,
            } => WalletCommand::ListUtxo {
                utxo_type,
                with_locked,
                utxo_states,
            },
            AccountGroupSubCommand::Balance {
                with_locked,
                utxo_states,
            } => WalletCommand::GetBalance {
                with_locked,
                utxo_states,
            },
            AccountGroupSubCommand::ShowXpub => {
                WalletCommand::ColdCommands(ColdWalletCommand::AccountExtendedPublicKey)
            }
        },
        WalletCommand::Address { command } => {
            match command {
                AddressGroupSubCommand::New => {
                    WalletCommand::ColdCommands(ColdWalletCommand::NewAddress)
                }
                AddressGroupSubCommand::List { include_change } => {
                    WalletCommand::ColdCommands(ColdWalletCommand::ShowAddresses { include_change })
                }
                AddressGroupSubCommand::Qr { address } => {
                    WalletCommand::ColdCommands(ColdWalletCommand::AddressQRCode { address })
                }
                AddressGroupSubCommand::RevealPublicKey {
                    public_key_hash,
                    format,
                } => WalletCommand::ColdCommands(match format {
                    CliPublicKeyFormat::Hex => {
                        ColdWalletCommand::RevealPublicKeyHex { public_key_hash }
                    }
                    CliPublicKeyFormat::Address => {
                        ColdWalletCommand::RevealPublicKey { public_key_hash }
                    }
                }),
                AddressGroupSubCommand::Sweep {
                    destination_address,
                    addresses,
                    all,
                } => WalletCommand::SweepFromAddress {
                    destination_address,
                    addresses,
                    all,
                },
                AddressGroupSubCommand::Standalone { command } => match command {
                    StandaloneGroupSubCommand::RenameLabel { address, label } => {
                        WalletCommand::StandaloneAddressLabelRename { address, label }
                    }
                    StandaloneGroupSubCommand::Add {
                        address,
                        label,
                        no_rescan,
                    } => WalletCommand::AddStandaloneKey {
                        address,
                        label,
                        no_rescan,
                    },
                    StandaloneGroupSubCommand::AddPrivateKey {
                        hex_private_key,
                        label,
                        no_rescan,
                    } => WalletCommand::AddStandalonePrivateKey {
                        hex_private_key,
                        label,
                        no_rescan,
                    },
                    StandaloneGroupSubCommand::AddMultisig {
                        min_required_signatures,
                        public_keys,
                        label,
                        no_rescan,
                    } => WalletCommand::AddStandaloneMultisig {
                        min_required_signatures,
                        public_keys,
                        label,
                        no_rescan,
                    },
                    StandaloneGroupSubCommand::List => {
                        WalletCommand::ColdCommands(ColdWalletCommand::ShowStandaloneAddresses)
                    }
                    StandaloneGroupSubCommand::Details { address } => WalletCommand::ColdCommands(
                        ColdWalletCommand::ShowStandaloneAddressDetails { address },
                    ),
                    StandaloneGroupSubCommand::Utxos {
                        utxo_type,
                        with_locked,
                        utxo_states,
                    } => WalletCommand::ListMultisigUtxo {
                        utxo_type,
                        with_locked,
                        utxo_states,
                    },
                },
            }
        }
        WalletCommand::Send {
            address,
            amount,
            utxos,
        } => WalletCommand::SendToAddress {
            address,
            amount,
            utxos,
        },
        WalletCommand::Data { command } => match command {
            DataGroupSubCommand::Deposit { hex_data } => WalletCommand::DepositData { hex_data },
        },
        WalletCommand::Staking { command } => match command {
            StakingGroupSubCommand::CreatePool {
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
                staker_address,
                vrf_public_key,
            } => WalletCommand::CreateStakePool {
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
                staker_address,
                vrf_public_key,
            },
            StakingGroupSubCommand::DecommissionPool {
                pool_id,
                output_address,
            } => WalletCommand::DecommissionStakePool {
                pool_id,
                output_address,
            },
            StakingGroupSubCommand::DecommissionPoolRequest {
                pool_id,
                output_address,
            } => WalletCommand::DecommissionStakePoolRequest {
                pool_id,
                output_address,
            },
            StakingGroupSubCommand::NewVrfPublicKey => {
                WalletCommand::ColdCommands(ColdWalletCommand::NewVrfPublicKey)
            }
            StakingGroupSubCommand::ShowVrfPublicKeys => {
                WalletCommand::ColdCommands(ColdWalletCommand::GetVrfPublicKey)
            }
            StakingGroupSubCommand::ShowLegacyVrfKey => {
                WalletCommand::ColdCommands(ColdWalletCommand::GetLegacyVrfPublicKey)
            }
            StakingGroupSubCommand::Start => WalletCommand::StartStaking,
            StakingGroupSubCommand::Stop => WalletCommand::StopStaking,
            StakingGroupSubCommand::Status => WalletCommand::StakingStatus,
            StakingGroupSubCommand::ListPools => WalletCommand::ListPools,
            StakingGroupSubCommand::ListOwnedPoolsForDecommission => {
                WalletCommand::ListOwnedPoolsForDecommission
            }
            StakingGroupSubCommand::ListCreatedBlocks => WalletCommand::ListCreatedBlocksIds,
            StakingGroupSubCommand::PoolBalance { pool_id } => {
                WalletCommand::StakePoolBalance { pool_id }
            }
        },
        WalletCommand::Delegation { command } => match command {
            DelegationGroupSubCommand::Create { owner, pool_id } => {
                WalletCommand::CreateDelegation { owner, pool_id }
            }
            DelegationGroupSubCommand::List => WalletCommand::ListDelegationIds,
            DelegationGroupSubCommand::Stake {
                amount,
                delegation_id,
            } => WalletCommand::DelegateStaking {
                amount,
                delegation_id,
            },
            DelegationGroupSubCommand::Withdraw {
                address,
                amount,
                delegation_id,
            } => WalletCommand::WithdrawFromDelegation {
                address,
                amount,
                delegation_id,
            },
            DelegationGroupSubCommand::Sweep {
                destination_address,
                delegation_id,
            } => WalletCommand::SweepFromDelegation {
                destination_address,
                delegation_id,
            },
        },
        WalletCommand::Token { command } => match command {
            TokenGroupSubCommand::Issue {
                token_ticker,
                number_of_decimals,
                metadata_uri,
                authority_address,
                token_supply,
                is_freezable,
            } => WalletCommand::IssueNewToken {
                token_ticker,
                number_of_decimals,
                metadata_uri,
                authority_address,
                token_supply,
                is_freezable,
            },
            TokenGroupSubCommand::Nft {
                command:
                    NftGroupSubCommand::Issue {
                        destination_address,
                        media_hash,
                        name,
                        description,
                        ticker,
                        creator,
                        icon_uri,
                        media_uri,
                        additional_metadata_uri,
                    },
            } => WalletCommand::IssueNewNft {
                destination_address,
                media_hash,
                name,
                description,
                ticker,
                creator,
                icon_uri,
                media_uri,
                additional_metadata_uri,
            },
            TokenGroupSubCommand::ChangeAuthority { token_id, address } => {
                WalletCommand::ChangeTokenAuthority { token_id, address }
            }
            TokenGroupSubCommand::ChangeMetadataUri {
                token_id,
                metadata_uri,
            } => WalletCommand::ChangeTokenMetadataUri {
                token_id,
                metadata_uri,
            },
            TokenGroupSubCommand::Mint {
                token_id,
                address,
                amount,
            } => WalletCommand::MintTokens {
                token_id,
                address,
                amount,
            },
            TokenGroupSubCommand::Unmint { token_id, amount } => {
                WalletCommand::UnmintTokens { token_id, amount }
            }
            TokenGroupSubCommand::LockSupply { token_id } => {
                WalletCommand::LockTokenSupply { token_id }
            }
            TokenGroupSubCommand::Freeze {
                token_id,
                is_unfreezable,
            } => WalletCommand::FreezeToken {
                token_id,
                is_unfreezable,
            },
            TokenGroupSubCommand::Unfreeze { token_id } => {
                WalletCommand::UnfreezeToken { token_id }
            }
            TokenGroupSubCommand::Send {
                token_id,
                address,
                amount,
            } => WalletCommand::SendTokensToAddress {
                token_id,
                address,
                amount,
            },
        },
        WalletCommand::Order { command } => match command {
            OrderGroupSubCommand::Create {
                ask_currency,
                ask_amount,
                give_currency,
                give_amount,
                conclude_address,
            } => WalletCommand::CreateOrder {
                ask_currency,
                ask_amount,
                give_currency,
                give_amount,
                conclude_address,
            },
            OrderGroupSubCommand::Fill {
                order_id,
                amount,
                output_address,
            } => WalletCommand::FillOrder {
                order_id,
                amount,
                output_address,
            },
            OrderGroupSubCommand::Freeze { order_id } => WalletCommand::FreezeOrder { order_id },
            OrderGroupSubCommand::Conclude {
                order_id,
                output_address,
            } => WalletCommand::ConcludeOrder {
                order_id,
                output_address,
            },
            OrderGroupSubCommand::ListOwn => WalletCommand::ListOwnOrders,
            OrderGroupSubCommand::ListAllActive {
                ask_currency,
                give_currency,
            } => WalletCommand::ListActiveOrders {
                ask_currency,
                give_currency,
            },
        },
        WalletCommand::Htlc { command } => match command {
            HtlcGroupSubCommand::Create {
                currency,
                amount,
                secret_hash,
                spend_address,
                refund_timelock,
                refund_address,
            } => WalletCommand::CreateHtlcTx {
                currency,
                amount,
                secret_hash,
                spend_address,
                refund_timelock,
                refund_address,
            },
            HtlcGroupSubCommand::GenerateSecret => WalletCommand::GenerateHtlcSecret,
            HtlcGroupSubCommand::CalcSecretHash { secret } => {
                WalletCommand::CalcHtlcSecretHash { secret }
            }
        },
        WalletCommand::Transaction { command } => match command {
            TransactionGroupSubCommand::Compose {
                outputs,
                utxos,
                only_transaction,
            } => WalletCommand::TransactionCompose {
                outputs,
                utxos,
                only_transaction,
            },
            TransactionGroupSubCommand::CreateFromColdInput {
                address,
                amount,
                utxo,
                change_address,
            } => WalletCommand::CreateTxFromColdInput {
                address,
                amount,
                utxo,
                change_address,
            },
            TransactionGroupSubCommand::Inspect { transaction } => {
                WalletCommand::InspectTransaction { transaction }
            }
            TransactionGroupSubCommand::Abandon { transaction_id } => {
                WalletCommand::AbandonTransaction { transaction_id }
            }
            TransactionGroupSubCommand::ListPending => WalletCommand::ListPendingTransactions,
            TransactionGroupSubCommand::ListByAddress { address, limit } => {
                WalletCommand::ListMainchainTransactions { address, limit }
            }
            TransactionGroupSubCommand::Get { transaction_id } => {
                WalletCommand::GetTransaction { transaction_id }
            }
            TransactionGroupSubCommand::GetRaw { transaction_id } => {
                WalletCommand::GetRawTransaction { transaction_id }
            }
            TransactionGroupSubCommand::GetSignedRaw { transaction_id } => {
                WalletCommand::GetRawSignedTransaction { transaction_id }
            }
        },
        command => command,
    }
}

fn format_tx_to_be_broadcasted(
    tx: HexEncoded<SignedTransaction>,
    fees: &Balances,
    chain_config: &ChainConfig,
) -> String {
    let hex = tx.to_string();
    let mut summary = tx.take().transaction().text_summary(chain_config);
    format_fees(&mut summary, fees);

    format!("{summary}\nThe transaction was created and is ready to be submitted:\n{hex}")
}

fn format_signature_status((idx, status): (usize, &RpcSignatureStatus)) -> String {
    let status = match status {
        RpcSignatureStatus::FullySigned => "FullySigned".to_owned(),
        RpcSignatureStatus::NotSigned => "NotSigned".to_owned(),
        RpcSignatureStatus::InvalidSignature => "InvalidSignature".to_owned(),
        RpcSignatureStatus::UnknownSignature => "UnknownSignature".to_owned(),
        RpcSignatureStatus::PartialMultisig {
            required_signatures,
            num_signatures,
        } => format!(
            "PartialMultisig having {num_signatures} out of {required_signatures} required signatures"
        ),
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

fn get_token_ids_from_order_infos<'a>(
    initial_balances_iter: impl Iterator<Item = (&'a RpcOutputValueOut, &'a RpcOutputValueOut)> + Clone,
) -> impl Iterator<Item = &'a RpcAddress<TokenId>> + Clone {
    initial_balances_iter
        .flat_map(|(balance1, balance2)| [balance1, balance2].into_iter())
        .flat_map(|balance| balance.token_id().into_iter())
}

fn get_token_ids_from_order_infos_as_str<'a>(
    initial_balances_iter: impl Iterator<Item = (&'a RpcOutputValueOut, &'a RpcOutputValueOut)> + Clone,
) -> Vec<String> {
    get_token_ids_from_order_infos(initial_balances_iter)
        .map(|rpc_addr| rpc_addr.as_str().to_owned())
        .collect_vec()
}

fn format_chainstate_info(info: &ChainInfo) -> String {
    format!(
        "Chainstate info:\n\
         \x20 Best block height: {}\n\
         \x20 Best block id: {}\n\
         \x20 Best block timestamp: {} ({})\n\
         \x20 Median time: {} ({})\n\
         \x20 Initial block download: {}",
        info.best_block_height,
        info.best_block_id,
        info.best_block_timestamp,
        info.best_block_timestamp.into_time(),
        info.median_time,
        info.median_time.into_time(),
        info.is_initial_block_download,
    )
}

fn format_staking_timestamps(timestamps: &BTreeMap<BlockHeight, Vec<BlockTimestamp>>) -> String {
    if timestamps.is_empty() {
        return "No staking timestamps found".to_owned();
    }

    let mut output = String::from("Staking timestamps by block height:");
    for (height, block_timestamps) in timestamps {
        let rendered = block_timestamps
            .iter()
            .map(|timestamp| format!("{} ({})", timestamp, timestamp.into_time()))
            .collect::<Vec<_>>()
            .join(", ");
        write!(output, "\n  {}: {}", height, rendered).expect("writing to a string cannot fail");
    }
    output
}

fn format_pending_transaction_ids(transactions: &[Id<Transaction>]) -> String {
    if transactions.is_empty() {
        return "No pending transactions".to_owned();
    }

    transactions
        .iter()
        .map(|id| format!("  {}", id_to_hex_string(*id.as_hash())))
        .join("\n")
}

fn format_connected_peers(peers: &[ConnectedPeer]) -> String {
    if peers.is_empty() {
        return "No connected peers".to_owned();
    }

    let mut table = prettytable::Table::new();
    table.set_titles(prettytable::row![
        "Peer id",
        "Address",
        "Role",
        "Ban score",
        "User agent",
    ]);
    table.extend(peers.iter().map(|peer| {
        prettytable::row![
            peer.peer_id,
            peer.address,
            format!("{:?}", peer.peer_role),
            peer.ban_score,
            peer.user_agent,
        ]
    }));
    table.to_string()
}

fn format_reserved_peers(peers: &[SocketAddress]) -> String {
    if peers.is_empty() {
        return "No reserved peers".to_owned();
    }

    let mut output = String::from("Reserved peers:");
    for (index, address) in peers.iter().enumerate() {
        write!(output, "\n  {}. {}", index + 1, address).expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod nested_translation_tests {
    use super::*;
    use clap::Parser;

    fn flat_debug(argv: &[&str]) -> String {
        let command = WalletCommand::try_parse_from(argv).expect("argv must parse");
        let flat = normalize_nested_wallet_command(command);
        assert!(
            !is_nested_wallet_command(&flat),
            "translation must produce a flat command"
        );
        format!("{flat:?}")
    }

    #[test]
    fn nested_spellings_translate_to_the_legacy_flat_commands() {
        const HEX_PRIVATE_KEY: &str =
            "001111111111111111111111111111111111111111111111111111111111111111";
        const HEX_TXID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        const UTXO_OUT_POINT_ARG: &str = concat!(
            "tx(",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            ",1)"
        );

        let cases: &[(&[&str], &[&str])] = &[
            (
                &["repl", "account", "create", "acc"],
                &["repl", "account-create", "acc"],
            ),
            (
                &["repl", "account", "rename", "acc"],
                &["repl", "account-rename", "acc"],
            ),
            (
                &["repl", "account", "select", "1"],
                &["repl", "account-select", "1"],
            ),
            (&["repl", "account", "utxos"], &["repl", "account-utxos"]),
            (
                &["repl", "account", "balance"],
                &["repl", "account-balance"],
            ),
            (
                &["repl", "account", "show-xpub"],
                &["repl", "account-extended-public-key-as-hex"],
            ),
            (&["repl", "address", "new"], &["repl", "address-new"]),
            (&["repl", "address", "list"], &["repl", "address-show"]),
            (
                &["repl", "address", "qr", "addr"],
                &["repl", "address-qrcode", "addr"],
            ),
            (
                &["repl", "address", "reveal-public-key", "pkh", "--format", "hex"],
                &["repl", "address-reveal-public-key-as-hex", "pkh"],
            ),
            (
                &["repl", "address", "reveal-public-key", "pkh"],
                &["repl", "address-reveal-public-key-as-address", "pkh"],
            ),
            (
                &["repl", "address", "sweep", "dest", "--all"],
                &["repl", "address-sweep-spendable", "dest", "--all"],
            ),
            (
                &["repl", "address", "standalone", "rename-label", "addr", "--label", "l"],
                &["repl", "standalone-address-label-rename", "addr", "--label", "l"],
            ),
            (
                &["repl", "address", "standalone", "add", "addr", "--no-rescan", "true"],
                &["repl", "standalone-add-watch-only-address", "addr", "--no-rescan", "true"],
            ),
            (
                &[
                    "repl",
                    "address",
                    "standalone",
                    "add-private-key",
                    HEX_PRIVATE_KEY,
                    "--no-rescan",
                    "true",
                ],
                &[
                    "repl",
                    "standalone-add-private-key-from-hex",
                    HEX_PRIVATE_KEY,
                    "--no-rescan",
                    "true",
                ],
            ),
            (
                &[
                    "repl",
                    "address",
                    "standalone",
                    "add-multisig",
                    "2",
                    "pk1",
                    "pk2",
                    "--no-rescan",
                    "true",
                ],
                &["repl", "standalone-add-multisig", "2", "pk1", "pk2", "--no-rescan", "true"],
            ),
            (
                &["repl", "address", "standalone", "list"],
                &["repl", "standalone-address-show"],
            ),
            (
                &["repl", "address", "standalone", "details", "addr"],
                &["repl", "standalone-address-details", "addr"],
            ),
            (
                &["repl", "address", "standalone", "utxos"],
                &["repl", "standalone-multisig-utxos"],
            ),
            (
                &["repl", "send", "dest", "1.0"],
                &["repl", "address-send", "dest", "1.0"],
            ),
            (
                &["repl", "data", "deposit", "deadbeef"],
                &["repl", "address-deposit-data", "deadbeef"],
            ),
            (
                &["repl", "staking", "new-vrf-public-key"],
                &["repl", "staking-new-vrf-public-key"],
            ),
            (
                &["repl", "staking", "show-vrf-public-keys"],
                &["repl", "staking-show-vrf-public-keys"],
            ),
            (
                &["repl", "staking", "show-legacy-vrf-key"],
                &["repl", "staking-show-legacy-vrf-key"],
            ),
            (
                &[
                    "repl",
                    "staking",
                    "create-pool",
                    "1000",
                    "0.01",
                    "0.1",
                    "decomm_addr",
                    "staker_addr",
                    "vrf_key",
                ],
                &[
                    "repl",
                    "staking-create-pool",
                    "1000",
                    "0.01",
                    "0.1",
                    "decomm_addr",
                    "staker_addr",
                    "vrf_key",
                ],
            ),
            (
                &["repl", "staking", "decommission-pool", "pool1", "out_addr"],
                &["repl", "staking-decommission-pool", "pool1", "out_addr"],
            ),
            (
                &["repl", "staking", "decommission-pool-request", "pool1", "out_addr"],
                &["repl", "staking-decommission-pool-request", "pool1", "out_addr"],
            ),
            (&["repl", "staking", "start"], &["repl", "staking-start"]),
            (&["repl", "staking", "stop"], &["repl", "staking-stop"]),
            (&["repl", "staking", "status"], &["repl", "staking-status"]),
            (
                &["repl", "staking", "list-pools"],
                &["repl", "staking-list-pools"],
            ),
            (
                &["repl", "staking", "list-owned-pools-for-decommission"],
                &["repl", "staking-list-owned-pools-for-decommission"],
            ),
            (
                &["repl", "staking", "list-created-blocks"],
                &["repl", "staking-list-created-block-ids"],
            ),
            (
                &["repl", "staking", "pool-balance", "pool1"],
                &["repl", "staking-pool-balance", "pool1"],
            ),
            (
                &["repl", "delegation", "create", "owner_addr", "pool1"],
                &["repl", "delegation-create", "owner_addr", "pool1"],
            ),
            (
                &["repl", "delegation", "list"],
                &["repl", "delegation-list-ids"],
            ),
            (
                &["repl", "delegation", "stake", "1.0", "deleg1"],
                &["repl", "delegation-stake", "1.0", "deleg1"],
            ),
            (
                &["repl", "delegation", "withdraw", "addr", "1.0", "deleg1"],
                &["repl", "delegation-withdraw", "addr", "1.0", "deleg1"],
            ),
            (
                &["repl", "delegation", "sweep", "dest", "deleg1"],
                &["repl", "staking-sweep-delegation", "dest", "deleg1"],
            ),
            (
                &[
                    "repl",
                    "token",
                    "issue",
                    "TKN",
                    "4",
                    "https://meta",
                    "authority_addr",
                    "unlimited",
                    "freezable",
                ],
                &[
                    "repl",
                    "token-issue-new",
                    "TKN",
                    "4",
                    "https://meta",
                    "authority_addr",
                    "unlimited",
                    "freezable",
                ],
            ),
            (
                &["repl", "token", "nft", "issue", "dest", "abcd", "name", "descr", "NFT"],
                &["repl", "token-nft-issue-new", "dest", "abcd", "name", "descr", "NFT"],
            ),
            (
                &["repl", "token", "change-authority", "tid", "addr"],
                &["repl", "token-change-authority", "tid", "addr"],
            ),
            (
                &["repl", "token", "change-metadata-uri", "tid", "uri"],
                &["repl", "token-change-metadata-uri", "tid", "uri"],
            ),
            (
                &["repl", "token", "mint", "tid", "addr", "1.0"],
                &["repl", "token-mint", "tid", "addr", "1.0"],
            ),
            (
                &["repl", "token", "unmint", "tid", "1.0"],
                &["repl", "token-unmint", "tid", "1.0"],
            ),
            (
                &["repl", "token", "lock-supply", "tid"],
                &["repl", "token-lock-supply", "tid"],
            ),
            (
                &["repl", "token", "freeze", "tid", "unfreezable"],
                &["repl", "token-freeze", "tid", "unfreezable"],
            ),
            (
                &["repl", "token", "unfreeze", "tid"],
                &["repl", "token-unfreeze", "tid"],
            ),
            (
                &["repl", "token", "send", "tid", "addr", "1.0"],
                &["repl", "token-send", "tid", "addr", "1.0"],
            ),
            (
                &["repl", "order", "create", "coin", "1.0", "coin", "2.0", "concl_addr"],
                &["repl", "order-create", "coin", "1.0", "coin", "2.0", "concl_addr"],
            ),
            (
                &["repl", "order", "fill", "ord1", "1.0", "out_addr"],
                &["repl", "order-fill", "ord1", "1.0", "out_addr"],
            ),
            (
                &["repl", "order", "freeze", "ord1"],
                &["repl", "order-freeze", "ord1"],
            ),
            (
                &["repl", "order", "conclude", "ord1", "out_addr"],
                &["repl", "order-conclude", "ord1", "out_addr"],
            ),
            (&["repl", "order", "list-own"], &["repl", "order-list-own"]),
            (
                &["repl", "order", "list-all-active", "--ask-currency", "coin"],
                &["repl", "order-list-all-active", "--ask-currency", "coin"],
            ),
            (
                &[
                    "repl",
                    "htlc",
                    "create",
                    "coin",
                    "1.0",
                    "secret_hash",
                    "spend_addr",
                    "block_count(720)",
                    "refund_addr",
                ],
                &[
                    "repl",
                    "htlc-create-transaction",
                    "coin",
                    "1.0",
                    "secret_hash",
                    "spend_addr",
                    "block_count(720)",
                    "refund_addr",
                ],
            ),
            (
                &["repl", "htlc", "generate-secret"],
                &["repl", "htlc-generate-secret"],
            ),
            (
                &["repl", "htlc", "calc-secret-hash", "s3cret"],
                &["repl", "htlc-calc-secret-hash", "s3cret"],
            ),
            (
                &["repl", "transaction", "compose", "transfer(addr,1.0)"],
                &["repl", "transaction-compose", "transfer(addr,1.0)"],
            ),
            (
                &[
                    "repl",
                    "transaction",
                    "create-from-cold-input",
                    "addr",
                    "1.0",
                    UTXO_OUT_POINT_ARG,
                    "--change",
                    "chg",
                ],
                &[
                    "repl",
                    "transaction-create-from-cold-input",
                    "addr",
                    "1.0",
                    UTXO_OUT_POINT_ARG,
                    "--change",
                    "chg",
                ],
            ),
            (
                &["repl", "transaction", "inspect", "deadbeef"],
                &["repl", "transaction-inspect", "deadbeef"],
            ),
            (
                &["repl", "transaction", "abandon", HEX_TXID],
                &["repl", "transaction-abandon", HEX_TXID],
            ),
            (
                &["repl", "transaction", "list-pending"],
                &["repl", "transaction-list-pending"],
            ),
            (
                &["repl", "transaction", "list-by-address", "addr", "--limit", "5"],
                &["repl", "transaction-list-by-address", "addr", "--limit", "5"],
            ),
            (
                &["repl", "transaction", "get", HEX_TXID],
                &["repl", "transaction-get", HEX_TXID],
            ),
            (
                &["repl", "transaction", "get-raw", HEX_TXID],
                &["repl", "transaction-get-raw", HEX_TXID],
            ),
            (
                &["repl", "transaction", "get-signed-raw", HEX_TXID],
                &["repl", "transaction-get-signed-raw", HEX_TXID],
            ),
            (
                &[
                    "repl",
                    "token",
                    "nft",
                    "issue",
                    "dest",
                    "abcd",
                    "name",
                    "descr",
                    "NFT",
                    "000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "https://icon",
                    "https://media",
                    "https://extra",
                ],
                &[
                    "repl",
                    "token-nft-issue-new",
                    "dest",
                    "abcd",
                    "name",
                    "descr",
                    "NFT",
                    "000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "https://icon",
                    "https://media",
                    "https://extra",
                ],
            ),
            (
                &[
                    "repl",
                    "order",
                    "list-all-active",
                    "--ask-currency",
                    "coin",
                    "--give-currency",
                    "token",
                ],
                &[
                    "repl",
                    "order-list-all-active",
                    "--ask-currency",
                    "coin",
                    "--give-currency",
                    "token",
                ],
            ),
            (
                &[
                    "repl",
                    "transaction",
                    "compose",
                    "transfer(addr,1.0)",
                    "--utxos",
                    UTXO_OUT_POINT_ARG,
                    "--only-transaction",
                ],
                &[
                    "repl",
                    "transaction-compose",
                    "transfer(addr,1.0)",
                    "--utxos",
                    UTXO_OUT_POINT_ARG,
                    "--only-transaction",
                ],
            ),
        ];

        for (nested, legacy) in cases {
            assert_eq!(
                flat_debug(nested),
                flat_debug(legacy),
                "nested {nested:?} must translate to legacy {legacy:?}"
            );
        }
    }
}
