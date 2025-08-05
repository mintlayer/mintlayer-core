// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{collections::BTreeMap, convert::identity, path::PathBuf, sync::Arc, time::Duration};

use chainstate::ChainInfo;
use common::{
    chain::{block::timestamp::BlockTimestamp, ChainConfig},
    primitives::{per_thousand::PerThousand, semver::SemVer, user_agent::UserAgent, Amount},
};
use iced::{
    widget::{center, container, Stack, Text},
    Element, Length, Task,
};
use logging::log;
use node_gui_backend::{
    messages::{
        BackendEvent, BackendRequest, EncryptionAction, SignedTransactionWrapper, TransactionInfo,
        WalletId, WalletInfo,
    },
    BackendSender, ImportOrCreate, InitializedNode,
};
use p2p::{net::types::services::Services, types::peer_id::PeerId, P2pEvent};
use rfd::AsyncFileDialog;
use wallet_cli_commands::ConsoleCommand;
use wallet_controller::types::WalletTypeArgs;
use wallet_types::{seed_phrase::StoreSeedPhrase, wallet_type::WalletType};

#[cfg(feature = "trezor")]
use crate::widgets::create_hw_wallet::hw_wallet_create_dialog;
use crate::{
    main_window::{main_menu::MenuMessage, main_widget::MainWidgetMessage},
    widgets::{
        confirm_broadcast::new_confirm_broadcast,
        esc_handler::esc_handler,
        new_wallet_account::new_wallet_account,
        opaque::opaque,
        popup_dialog::{popup_dialog, Popup},
        wallet_mnemonic::wallet_mnemonic_dialog,
        wallet_set_password::wallet_set_password_dialog,
        wallet_unlock::wallet_unlock_dialog,
    },
    WalletMode,
};

use self::main_widget::tabs::{wallet::WalletMessage, TabsMessage};

mod main_menu;
mod main_widget;

#[derive(Debug, PartialEq, Eq)]
enum ActiveDialog {
    None,
    WalletCreate { wallet_args: WalletArgs },
    WalletRecover { wallet_type: WalletType },
    WalletSetPassword { wallet_id: WalletId },
    WalletUnlock { wallet_id: WalletId },
    NewAccount { wallet_id: WalletId },
    ConfirmTransaction { transaction_info: TransactionInfo },
}

#[derive(Debug)]
pub struct NodeState {
    chain_config: Arc<ChainConfig>,
    chain_info: ChainInfo,
    connected_peers: BTreeMap<PeerId, Peer>,
    wallets: BTreeMap<WalletId, WalletInfo>,
}

impl NodeState {
    pub fn chain_config(&self) -> &ChainConfig {
        &self.chain_config
    }
}

fn print_coin_amount(chain_config: &ChainConfig, value: Amount) -> String {
    value.into_fixedpoint_str(chain_config.coin_decimals())
}

fn print_margin_ratio(value: PerThousand) -> String {
    value.to_percentage_str()
}

fn print_coin_amount_with_ticker(chain_config: &ChainConfig, value: Amount) -> String {
    format!(
        "{} {}",
        print_coin_amount(chain_config, value),
        chain_config.coin_ticker()
    )
}

fn print_timestamp(timestamp: Duration) -> Option<String> {
    let timestamp: i64 = timestamp.as_secs().try_into().ok()?;
    let timestamp = chrono::DateTime::from_timestamp(timestamp, 0);

    // To print in local timezone
    // use chrono::TimeZone;
    // let timestamp = chrono::Local.from_utc_datetime(&timestamp);

    timestamp.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn print_block_timestamp(timestamp: BlockTimestamp) -> String {
    print_timestamp(timestamp.as_duration_since_epoch())
        .unwrap_or_else(|| "Invalid timestamp".to_owned())
}

#[derive(Debug)]
pub struct Peer {
    address: String,
    inbound: bool,
    _services: Services,
    user_agent: UserAgent,
    version: SemVer,
}

pub struct MainWindow {
    main_menu: main_menu::MainMenu,
    main_widget: main_widget::MainWidget,
    language: wallet::wallet::Language,
    node_state: NodeState,
    popups: Vec<Popup>,
    active_dialog: ActiveDialog,

    /// Disable the UI (by showing a modal widget) if a file dialog is active.
    /// Without this it is possible to open multiple file dialogs (which we don't want).
    file_dialog_active: bool,
    wallet_msg: Option<WalletMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletArgs {
    Software {
        mnemonic: String,
        is_cold: bool,
    },
    #[cfg(feature = "trezor")]
    Trezor,
}

impl From<&WalletArgs> for WalletType {
    fn from(value: &WalletArgs) -> Self {
        match value {
            WalletArgs::Software {
                mnemonic: _,
                is_cold,
            } => {
                if *is_cold {
                    WalletType::Cold
                } else {
                    WalletType::Hot
                }
            }
            #[cfg(feature = "trezor")]
            WalletArgs::Trezor => WalletType::Trezor,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MainWindowMessage {
    MenuMessage(main_menu::MenuMessage),
    MainWidgetMessage(main_widget::MainWidgetMessage),
    FromBackend(BackendEvent),

    OpenWalletFileSelected {
        file_path: PathBuf,
        wallet_type: WalletType,
    },
    OpenWalletFileCanceled,

    ImportWalletMnemonic {
        args: WalletArgs,
        import: ImportOrCreate,
    },
    ImportWalletFileSelected {
        wallet_args: WalletTypeArgs,
        file_path: PathBuf,
        import: ImportOrCreate,
        wallet_type: WalletType,
    },
    ImportWalletFileCanceled,

    WalletSetPassword {
        wallet_id: WalletId,
        password1: String,
        password2: String,
    },
    WalletUnlock {
        wallet_id: WalletId,
        password: String,
    },

    NewWalletAccount {
        wallet_id: WalletId,
        name: String,
    },

    SubmitTx {
        wallet_id: WalletId,
        tx: SignedTransactionWrapper,
    },

    CopyToClipboard(String),
    ClosePopup,
    CloseDialog,
}

impl MainWindow {
    pub fn new(initialized_node: InitializedNode, wallet_mode: WalletMode) -> Self {
        let InitializedNode {
            chain_config,
            chain_info,
        } = initialized_node;

        let node_state = NodeState {
            chain_config,
            chain_info,
            connected_peers: BTreeMap::new(),
            wallets: BTreeMap::new(),
        };

        Self {
            main_menu: main_menu::MainMenu::new(wallet_mode),
            main_widget: main_widget::MainWidget::new(wallet_mode),
            // TODO: Support other languages
            language: wallet::wallet::Language::English,
            node_state,
            popups: Vec::new(),
            active_dialog: ActiveDialog::None,
            file_dialog_active: false,
            wallet_msg: None,
        }
    }

    pub fn node_state(&self) -> &NodeState {
        &self.node_state
    }

    pub fn show_error(&mut self, message: String) {
        self.popups.push(Popup {
            title: "Error".to_owned(),
            message,
        })
    }

    pub fn show_info(&mut self, message: String) {
        self.popups.push(Popup {
            title: "Info".to_owned(),
            message,
        })
    }

    pub fn update(
        &mut self,
        msg: MainWindowMessage,
        backend_sender: &BackendSender,
    ) -> Task<MainWindowMessage> {
        match msg {
            MainWindowMessage::MenuMessage(menu_message) => {
                // Note: iced_aw's menu has an annoying bug/feature - when a menu item is clicked, the drop down menu
                // won't close automatically, allowing the user to continue clicking on menu items.
                // E.g. see https://github.com/iced-rs/iced_aw/issues/312
                // This allows the user to mess things up by opening dialogs on top of dialogs; to prevent this,
                // we first check if a dialog is already open and ignore the event in such a case.
                if self.active_dialog != ActiveDialog::None || self.file_dialog_active {
                    Task::none()
                } else {
                    match menu_message {
                        MenuMessage::NoOp => Task::none(),
                        MenuMessage::CreateNewWallet { wallet_type } => {
                            let wallet_args = match wallet_type {
                                WalletType::Hot | WalletType::Cold => WalletArgs::Software {
                                    mnemonic: wallet_controller::mnemonic::generate_new_mnemonic(
                                        self.language,
                                    )
                                    .to_string(),
                                    is_cold: wallet_type == WalletType::Cold,
                                },
                                #[cfg(feature = "trezor")]
                                WalletType::Trezor => WalletArgs::Trezor,
                            };
                            self.active_dialog = ActiveDialog::WalletCreate { wallet_args };
                            Task::none()
                        }
                        MenuMessage::RecoverWallet { wallet_type } => {
                            self.active_dialog = ActiveDialog::WalletRecover { wallet_type };
                            Task::none()
                        }
                        MenuMessage::OpenWallet { wallet_type } => {
                            self.file_dialog_active = true;
                            Task::perform(
                                async move {
                                    let file_opt = AsyncFileDialog::new().pick_file().await;
                                    if let Some(file) = file_opt {
                                        log::info!("Open wallet file: {file:?}");
                                        MainWindowMessage::OpenWalletFileSelected {
                                            file_path: file.path().to_owned(),
                                            wallet_type,
                                        }
                                    } else {
                                        MainWindowMessage::OpenWalletFileCanceled
                                    }
                                },
                                identity,
                            )
                        }
                        MenuMessage::Exit => {
                            iced::window::get_latest().and_then(iced::window::close)
                        }
                    }
                }
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::SetPassword),
            )) => {
                self.active_dialog = ActiveDialog::WalletSetPassword { wallet_id };
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::RemovePassword),
            )) => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::RemovePassword,
                });
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::Lock),
            )) => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::Lock,
                });
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::Unlock),
            )) => {
                self.active_dialog = ActiveDialog::WalletUnlock { wallet_id };
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::NewAccount),
            )) => {
                self.active_dialog = ActiveDialog::NewAccount { wallet_id };
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(_wallet_id, WalletMessage::StillSyncing),
            )) => {
                self.show_info("The wallet is still syncing...".into());
                Task::none()
            }

            MainWindowMessage::MainWidgetMessage(main_widget_message) => self
                .main_widget
                .update(main_widget_message, backend_sender)
                .map(MainWindowMessage::MainWidgetMessage),

            MainWindowMessage::FromBackend(from_msg) => match from_msg {
                BackendEvent::ChainInfo(chain_info) => {
                    self.node_state.chain_info = chain_info;
                    Task::none()
                }
                BackendEvent::P2p(P2pEvent::PeerConnected {
                    id,
                    services,
                    address,
                    inbound,
                    user_agent,
                    software_version: version,
                }) => {
                    self.node_state.connected_peers.insert(
                        id,
                        Peer {
                            address,
                            inbound,
                            _services: services,
                            user_agent,
                            version,
                        },
                    );
                    Task::none()
                }
                BackendEvent::P2p(P2pEvent::PeerDisconnected(peer_id)) => {
                    self.node_state.connected_peers.remove(&peer_id);
                    Task::none()
                }

                BackendEvent::OpenWallet(Ok(wallet_info))
                | BackendEvent::ImportWallet(Ok(wallet_info)) => {
                    self.active_dialog = ActiveDialog::None;
                    let wallet_id = wallet_info.wallet_id;
                    let wallet_type = wallet_info.wallet_type;
                    self.node_state.wallets.insert(wallet_id, wallet_info);

                    Task::done(MainWindowMessage::MainWidgetMessage(
                        MainWidgetMessage::WalletAdded {
                            wallet_id,
                            wallet_type,
                        },
                    ))
                }

                BackendEvent::OpenWallet(Err(error)) | BackendEvent::ImportWallet(Err(error)) => {
                    self.show_error(error.to_string());
                    self.file_dialog_active = false;
                    self.active_dialog = ActiveDialog::None;
                    Task::none()
                }

                BackendEvent::CloseWallet(wallet_id) => Task::perform(async {}, move |_| {
                    MainWindowMessage::MainWidgetMessage(MainWidgetMessage::WalletRemoved(
                        wallet_id,
                    ))
                }),

                BackendEvent::UpdateEncryption(Ok((wallet_id, encryption))) => {
                    self.active_dialog = ActiveDialog::None;
                    if let Some(wallet) = self.node_state.wallets.get_mut(&wallet_id) {
                        wallet.encryption = encryption;
                    }
                    Task::none()
                }
                BackendEvent::UpdateEncryption(Err(err)) => {
                    self.active_dialog = ActiveDialog::None;
                    self.show_error(err.to_string());
                    Task::none()
                }

                BackendEvent::NewAccount(Ok((wallet_id, account_id, account_info))) => {
                    self.active_dialog = ActiveDialog::None;
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (NewAccount)")
                        .accounts
                        .insert(account_id, account_info);
                    Task::none()
                }
                BackendEvent::NewAccount(Err(err)) => {
                    self.show_error(err.to_string());
                    Task::none()
                }

                BackendEvent::WalletBestBlock(wallet_id, best_block) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (BestBlock)")
                        .best_block = best_block;
                    Task::none()
                }

                BackendEvent::Balance(wallet_id, account_id, balance) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (balance)")
                        .accounts
                        .get_mut(&account_id)
                        .expect("account must be known (balance)")
                        .balance = balance;
                    Task::none()
                }
                BackendEvent::StakingBalance(wallet_id, account_id, staking_balance) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (staking balance)")
                        .accounts
                        .get_mut(&account_id)
                        .expect("account must be known (staking balance)")
                        .staking_balance = staking_balance;
                    Task::none()
                }
                BackendEvent::DelegationsBalance(wallet_id, account_id, delegations_balance) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (staking balance)")
                        .accounts
                        .get_mut(&account_id)
                        .expect("account must be known (staking balance)")
                        .delegations_balance = delegations_balance;
                    Task::none()
                }
                BackendEvent::NewAddress(Ok(address_info)) => {
                    self.node_state
                        .wallets
                        .get_mut(&address_info.wallet_id)
                        .expect("wallet must be known (NewAddress)")
                        .accounts
                        .get_mut(&address_info.account_id)
                        .expect("account must be known (NewAddress)")
                        .addresses
                        .insert(address_info.index, address_info.address);
                    Task::none()
                }
                BackendEvent::NewAddress(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::ToggleStaking(Ok((wallet_id, account_id, enabled))) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (ToggleStaking)")
                        .accounts
                        .get_mut(&account_id)
                        .expect("account must be known (ToggleStaking)")
                        .staking_enabled = enabled;
                    Task::none()
                }
                BackendEvent::ToggleStaking(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::SendAmount(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::SendSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::SendAmount(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::StakeAmount(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::CreateStakingPoolSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::StakeAmount(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::DecommissionPool(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::DecommissionPoolSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::DecommissionPool(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::CreateDelegation(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::CreateDelegationSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::CreateDelegation(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::DelegateStaking(Ok((transaction_info, delegation_id))) => {
                    self.wallet_msg = Some(WalletMessage::DelegateStakingSucceed(delegation_id));
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::DelegateStaking(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::SendDelegationToAddress(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::SendDelegationToAddressSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Task::none()
                }
                BackendEvent::SendDelegationToAddress(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::Broadcast(Ok(wallet_id)) => {
                    self.active_dialog = ActiveDialog::None;
                    self.show_info(
                        "Success. Please wait for your transaction to be included in a block."
                            .to_owned(),
                    );

                    if let Some(wallet_msg) = self.wallet_msg.take() {
                        self.main_widget
                            .update(
                                MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                                    wallet_id, wallet_msg,
                                )),
                                backend_sender,
                            )
                            .map(MainWindowMessage::MainWidgetMessage)
                    } else {
                        Task::none()
                    }
                }
                BackendEvent::Broadcast(Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::TransactionList(wallet_id, account_id, Ok(transaction_list)) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (TransactionList)")
                        .accounts
                        .get_mut(&account_id)
                        .expect("account must be known (TransactionList)")
                        .transaction_list = transaction_list;
                    Task::none()
                }
                BackendEvent::TransactionList(_wallet_id, _account_id, Err(error)) => {
                    self.show_error(error.to_string());
                    Task::none()
                }
                BackendEvent::ConsoleResponse(wallet_id, _account_id, Ok(command)) => match command
                {
                    ConsoleCommand::SetStatus {
                        status: _,
                        print_message: out,
                    }
                    | ConsoleCommand::Print(out) => self
                        .main_widget
                        .update(
                            MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                                wallet_id,
                                WalletMessage::ConsoleOutput(out),
                            )),
                            backend_sender,
                        )
                        .map(MainWindowMessage::MainWidgetMessage),
                    ConsoleCommand::PaginatedPrint { header, body } => self
                        .main_widget
                        .update(
                            MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                                wallet_id,
                                WalletMessage::ConsoleOutput(header + &body),
                            )),
                            backend_sender,
                        )
                        .map(MainWindowMessage::MainWidgetMessage),
                    ConsoleCommand::ChoiceMenu(menu) => self
                        .main_widget
                        .update(
                            MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                                wallet_id,
                                WalletMessage::ConsoleOutput(format!(
                                    "{}\n{}",
                                    menu.header(),
                                    menu.choice_list().join("\n")
                                )),
                            )),
                            backend_sender,
                        )
                        .map(MainWindowMessage::MainWidgetMessage),
                    ConsoleCommand::ClearScreen
                    | ConsoleCommand::ClearHistory
                    | ConsoleCommand::PrintHistory
                    | ConsoleCommand::Exit => self
                        .main_widget
                        .update(
                            MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                                wallet_id,
                                WalletMessage::ConsoleOutput(String::new()),
                            )),
                            backend_sender,
                        )
                        .map(MainWindowMessage::MainWidgetMessage),
                },
                BackendEvent::ConsoleResponse(wallet_id, _account_id, Err(error)) => self
                    .main_widget
                    .update(
                        MainWidgetMessage::TabsMessage(TabsMessage::WalletMessage(
                            wallet_id,
                            WalletMessage::ConsoleOutput(error.to_string()),
                        )),
                        backend_sender,
                    )
                    .map(MainWindowMessage::MainWidgetMessage),
            },
            MainWindowMessage::OpenWalletFileSelected {
                file_path,
                wallet_type,
            } => {
                self.file_dialog_active = false;
                backend_sender.send(BackendRequest::OpenWallet {
                    file_path,
                    wallet_type,
                });
                Task::none()
            }
            MainWindowMessage::OpenWalletFileCanceled => {
                self.file_dialog_active = false;
                Task::none()
            }

            MainWindowMessage::ImportWalletMnemonic { args, import } => {
                let wallet_type = (&args).into();
                let wallet_args = match args {
                    WalletArgs::Software {
                        mnemonic,
                        is_cold: _,
                    } => {
                        let mnemonic_res =
                            wallet_controller::mnemonic::parse_mnemonic(self.language, &mnemonic);
                        match mnemonic_res {
                            Ok(mnemonic) => WalletTypeArgs::Software {
                                mnemonic: Some(mnemonic.to_string()),
                                passphrase: None,
                                store_seed_phrase: StoreSeedPhrase::Store,
                            },
                            Err(err) => {
                                self.show_error(err.to_string());
                                return Task::none();
                            }
                        }
                    }
                    #[cfg(feature = "trezor")]
                    WalletArgs::Trezor => WalletTypeArgs::Trezor { device_id: None },
                };

                self.file_dialog_active = true;
                Task::perform(
                    async move {
                        let file_opt = AsyncFileDialog::new().save_file().await;
                        if let Some(file) = file_opt {
                            log::info!("Save wallet file: {file:?}");
                            MainWindowMessage::ImportWalletFileSelected {
                                wallet_args,
                                file_path: file.path().to_owned(),
                                import,
                                wallet_type,
                            }
                        } else {
                            MainWindowMessage::ImportWalletFileCanceled
                        }
                    },
                    identity,
                )
            }
            MainWindowMessage::ImportWalletFileSelected {
                wallet_args,
                file_path,
                import,
                wallet_type,
            } => {
                self.file_dialog_active = false;

                backend_sender.send(BackendRequest::RecoverWallet {
                    wallet_args,
                    file_path,
                    import,
                    wallet_type,
                });
                Task::none()
            }
            MainWindowMessage::ImportWalletFileCanceled => {
                self.file_dialog_active = false;
                self.active_dialog = ActiveDialog::None;
                Task::none()
            }

            MainWindowMessage::WalletSetPassword {
                wallet_id,
                password1,
                password2,
            } => {
                if password1 != password2 {
                    self.show_error("Passwords do not match".to_string());
                } else {
                    backend_sender.send(BackendRequest::UpdateEncryption {
                        wallet_id,
                        action: EncryptionAction::SetPassword(password1),
                    });
                }
                Task::none()
            }

            MainWindowMessage::WalletUnlock {
                wallet_id,
                password,
            } => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::Unlock(password),
                });
                Task::none()
            }

            MainWindowMessage::NewWalletAccount { wallet_id, name } => {
                backend_sender.send(BackendRequest::NewAccount { wallet_id, name });
                Task::none()
            }

            MainWindowMessage::SubmitTx { wallet_id, tx } => {
                backend_sender.send(BackendRequest::SubmitTx { wallet_id, tx });
                Task::none()
            }

            MainWindowMessage::CopyToClipboard(text) => iced::clipboard::write(text),

            MainWindowMessage::ClosePopup => {
                self.popups.pop();
                Task::none()
            }
            MainWindowMessage::CloseDialog => {
                self.active_dialog = ActiveDialog::None;
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<MainWindowMessage> {
        let main_content = iced::widget::column![
            self.main_menu.view().map(MainWindowMessage::MenuMessage),
            self.main_widget
                .view(&self.node_state)
                .map(MainWindowMessage::MainWidgetMessage),
        ];

        let show_dialog = self.active_dialog != ActiveDialog::None;
        let dialog = show_dialog
            .then(move || -> Element<MainWindowMessage> {
                match &self.active_dialog {
                    ActiveDialog::None => Text::new("Nothing to show").into(),

                    ActiveDialog::WalletCreate { wallet_args } => match wallet_args {
                        WalletArgs::Software { mnemonic, is_cold } => {
                            let is_cold = *is_cold;
                            wallet_mnemonic_dialog(
                                Some(mnemonic.clone()),
                                Box::new(move |mnemonic| MainWindowMessage::ImportWalletMnemonic {
                                    args: WalletArgs::Software { mnemonic, is_cold },
                                    import: ImportOrCreate::Create,
                                }),
                                Box::new(|| MainWindowMessage::CloseDialog),
                                Box::new(MainWindowMessage::CopyToClipboard),
                            )
                            .into()
                        }
                        #[cfg(feature = "trezor")]
                        WalletArgs::Trezor => hw_wallet_create_dialog(
                            Box::new(move || MainWindowMessage::ImportWalletMnemonic {
                                args: WalletArgs::Trezor,
                                import: ImportOrCreate::Create,
                            }),
                            Box::new(|| MainWindowMessage::CloseDialog),
                            ImportOrCreate::Create,
                        )
                        .into(),
                    },
                    ActiveDialog::WalletRecover { wallet_type } => {
                        let is_cold = *wallet_type == WalletType::Cold;
                        match wallet_type {
                            WalletType::Hot | WalletType::Cold => wallet_mnemonic_dialog(
                                None,
                                Box::new(move |mnemonic| MainWindowMessage::ImportWalletMnemonic {
                                    args: WalletArgs::Software { mnemonic, is_cold },
                                    import: ImportOrCreate::Import,
                                }),
                                Box::new(|| MainWindowMessage::CloseDialog),
                                Box::new(MainWindowMessage::CopyToClipboard),
                            )
                            .into(),
                            #[cfg(feature = "trezor")]
                            WalletType::Trezor => hw_wallet_create_dialog(
                                Box::new(move || MainWindowMessage::ImportWalletMnemonic {
                                    args: WalletArgs::Trezor,
                                    import: ImportOrCreate::Create,
                                }),
                                Box::new(|| MainWindowMessage::CloseDialog),
                                ImportOrCreate::Import,
                            )
                            .into(),
                        }
                    }

                    ActiveDialog::WalletSetPassword { wallet_id } => {
                        let wallet_id = *wallet_id;
                        wallet_set_password_dialog(
                            Box::new(move |password1, password2| {
                                MainWindowMessage::WalletSetPassword {
                                    wallet_id,
                                    password1,
                                    password2,
                                }
                            }),
                            Box::new(|| MainWindowMessage::CloseDialog),
                        )
                        .into()
                    }

                    ActiveDialog::WalletUnlock { wallet_id } => {
                        let wallet_id = *wallet_id;
                        wallet_unlock_dialog(
                            Box::new(move |password| MainWindowMessage::WalletUnlock {
                                wallet_id,
                                password,
                            }),
                            Box::new(|| MainWindowMessage::CloseDialog),
                        )
                        .into()
                    }

                    ActiveDialog::NewAccount { wallet_id } => {
                        let wallet_id = *wallet_id;
                        new_wallet_account(
                            Box::new(move |name| MainWindowMessage::NewWalletAccount {
                                wallet_id,
                                name,
                            }),
                            Box::new(|| MainWindowMessage::CloseDialog),
                        )
                        .into()
                    }

                    ActiveDialog::ConfirmTransaction { transaction_info } => {
                        let wallet_id = transaction_info.wallet_id;
                        new_confirm_broadcast(
                            Box::new(move |tx| MainWindowMessage::SubmitTx { wallet_id, tx }),
                            Box::new(|| MainWindowMessage::CloseDialog),
                            Box::new(MainWindowMessage::CopyToClipboard),
                            transaction_info.tx.clone(),
                            self.node_state.chain_config.clone(),
                        )
                        .into()
                    }
                }
            })
            .map(|d| {
                esc_handler(
                    centered_with_opaque_blurred_bg(d),
                    Some(MainWindowMessage::CloseDialog),
                )
            });

        let popup: Option<Element<MainWindowMessage>> =
            match (self.file_dialog_active, self.popups.last()) {
                (true, _) => Some(bordered_text_on_normal_bg("File dialog...")),
                (_, Some(popup)) => {
                    Some(popup_dialog(popup.clone(), MainWindowMessage::ClosePopup).into())
                }
                (_, None) => None,
            };
        let popup = popup.map(|d| {
            esc_handler(
                centered_with_opaque_blurred_bg(d),
                (!self.file_dialog_active).then_some(MainWindowMessage::ClosePopup),
            )
        });

        Stack::with_children(std::iter::once(main_content.into()).chain(dialog).chain(popup))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

fn bordered_text_on_normal_bg<'a, Message: 'a>(text: &'a str) -> Element<'a, Message> {
    container(Text::new(text))
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();

            container::Style {
                background: Some(palette.background.base.color.into()),
                border: iced::Border {
                    width: 1.0,
                    radius: 2.0.into(),
                    color: palette.background.strong.color,
                },
                ..container::Style::default()
            }
        })
        .padding([5, 10])
        .into()
}

/// Create a container that
/// 1) fills all the available space and centers the provided content inside;
/// 2) is opaque to mouse events;
/// 3) uses semi-transparent white as the background, which creates the blurred background effect.
fn centered_with_opaque_blurred_bg<'a, Message: 'a>(
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    opaque(center(content).style(|_theme| {
        container::Style {
            background: Some(
                iced::Color {
                    a: 0.5,
                    ..iced::Color::WHITE
                }
                .into(),
            ),
            ..container::Style::default()
        }
    }))
}
