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
    chain::{block::timestamp::BlockTimestamp, ChainConfig, SignedTransaction},
    primitives::{per_thousand::PerThousand, semver::SemVer, user_agent::UserAgent, Amount},
};
use iced::{widget::Text, window, Command, Element};
use iced_aw::native::Modal;
use logging::log;
use p2p::{net::types::services::Services, types::peer_id::PeerId, P2pEvent};
use rfd::AsyncFileDialog;

use crate::{
    backend::{
        messages::{
            BackendEvent, BackendRequest, EncryptionAction, TransactionInfo, WalletId, WalletInfo,
        },
        BackendSender, InitializedNode,
    },
    main_window::{main_menu::MenuMessage, main_widget::MainWidgetMessage},
    widgets::{
        confirm_broadcast::new_confirm_broadcast,
        new_wallet_account::new_wallet_account,
        popup_dialog::{popup_dialog, Popup},
        wallet_mnemonic::wallet_mnemonic_dialog,
        wallet_set_password::wallet_set_password_dialog,
        wallet_unlock::wallet_unlock_dialog,
    },
};

use self::main_widget::tabs::{wallet::WalletMessage, TabsMessage};

mod main_menu;
mod main_widget;

#[derive(Debug, PartialEq, Eq)]
enum ActiveDialog {
    None,
    WalletCreate {
        generated_mnemonic: wallet_controller::mnemonic::Mnemonic,
    },
    WalletImport,
    WalletSetPassword {
        wallet_id: WalletId,
    },
    WalletUnlock {
        wallet_id: WalletId,
    },
    NewAccount {
        wallet_id: WalletId,
    },
    ConfirmTransaction {
        transaction_info: TransactionInfo,
    },
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
    value.into_percentage_str()
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

#[derive(Debug, Clone, Copy)]
pub enum ImportOrCreate {
    Import,
    Create,
}

#[derive(Debug, Clone)]
pub enum MainWindowMessage {
    MenuMessage(main_menu::MenuMessage),
    MainWidgetMessage(main_widget::MainWidgetMessage),
    FromBackend(BackendEvent),

    OpenWalletFileSelected {
        file_path: PathBuf,
    },
    OpenWalletFileCanceled,

    ImportWalletMnemonic {
        mnemonic: String,
        import: ImportOrCreate,
    },
    ImportWalletFileSelected {
        mnemonic: wallet_controller::mnemonic::Mnemonic,
        file_path: PathBuf,
        import: ImportOrCreate,
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
        tx: SignedTransaction,
    },

    CopyToClipboard(String),
    ClosePopup,
    CloseDialog,
}

impl MainWindow {
    pub fn new(initialized_node: InitializedNode) -> Self {
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
            main_menu: main_menu::MainMenu::new(),
            main_widget: main_widget::MainWidget::new(),
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
    ) -> Command<MainWindowMessage> {
        match msg {
            MainWindowMessage::MenuMessage(menu_message) => match menu_message {
                MenuMessage::NoOp => Command::none(),
                MenuMessage::CreateNewWallet => {
                    let generated_mnemonic =
                        wallet_controller::mnemonic::generate_new_mnemonic(self.language);
                    self.active_dialog = ActiveDialog::WalletCreate { generated_mnemonic };
                    Command::none()
                }
                MenuMessage::ImportWallet => {
                    self.active_dialog = ActiveDialog::WalletImport;
                    Command::none()
                }
                MenuMessage::OpenWallet => {
                    self.file_dialog_active = true;
                    Command::perform(
                        async move {
                            let file_opt = AsyncFileDialog::new().pick_file().await;
                            if let Some(file) = file_opt {
                                log::info!("Open wallet file: {file:?}");
                                MainWindowMessage::OpenWalletFileSelected {
                                    file_path: file.path().to_owned(),
                                }
                            } else {
                                MainWindowMessage::OpenWalletFileCanceled
                            }
                        },
                        identity,
                    )
                }
                MenuMessage::Exit => iced::window::close(window::Id::MAIN),
            },

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::SetPassword),
            )) => {
                self.active_dialog = ActiveDialog::WalletSetPassword { wallet_id };
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::RemovePassword),
            )) => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::RemovePassword,
                });
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::Lock),
            )) => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::Lock,
                });
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::Unlock),
            )) => {
                self.active_dialog = ActiveDialog::WalletUnlock { wallet_id };
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(wallet_id, WalletMessage::NewAccount),
            )) => {
                self.active_dialog = ActiveDialog::NewAccount { wallet_id };
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(MainWidgetMessage::TabsMessage(
                TabsMessage::WalletMessage(_wallet_id, WalletMessage::StillSyncing),
            )) => {
                self.show_info("The wallet is still syncing...".into());
                Command::none()
            }

            MainWindowMessage::MainWidgetMessage(main_widget_message) => self
                .main_widget
                .update(main_widget_message, backend_sender)
                .map(MainWindowMessage::MainWidgetMessage),

            MainWindowMessage::FromBackend(from_msg) => match from_msg {
                BackendEvent::ChainInfo(chain_info) => {
                    self.node_state.chain_info = chain_info;
                    Command::none()
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
                    Command::none()
                }
                BackendEvent::P2p(P2pEvent::PeerDisconnected(peer_id)) => {
                    self.node_state.connected_peers.remove(&peer_id);
                    Command::none()
                }

                BackendEvent::OpenWallet(Ok(wallet_info))
                | BackendEvent::ImportWallet(Ok(wallet_info)) => {
                    self.active_dialog = ActiveDialog::None;
                    let wallet_id = wallet_info.wallet_id;
                    self.node_state.wallets.insert(wallet_id, wallet_info);

                    Command::perform(async {}, move |_| {
                        MainWindowMessage::MainWidgetMessage(MainWidgetMessage::WalletAdded(
                            wallet_id,
                        ))
                    })
                }

                BackendEvent::OpenWallet(Err(error)) | BackendEvent::ImportWallet(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }

                BackendEvent::CloseWallet(wallet_id) => Command::perform(async {}, move |_| {
                    MainWindowMessage::MainWidgetMessage(MainWidgetMessage::WalletRemoved(
                        wallet_id,
                    ))
                }),

                BackendEvent::UpdateEncryption(Ok((wallet_id, encryption))) => {
                    self.active_dialog = ActiveDialog::None;
                    if let Some(wallet) = self.node_state.wallets.get_mut(&wallet_id) {
                        wallet.encryption = encryption;
                    }
                    Command::none()
                }
                BackendEvent::UpdateEncryption(Err(err)) => {
                    self.active_dialog = ActiveDialog::None;
                    self.show_error(err.to_string());
                    Command::none()
                }

                BackendEvent::NewAccount(Ok((wallet_id, account_id, account_info))) => {
                    self.active_dialog = ActiveDialog::None;
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (NewAccount)")
                        .accounts
                        .insert(account_id, account_info);
                    Command::none()
                }
                BackendEvent::NewAccount(Err(err)) => {
                    self.show_error(err.to_string());
                    Command::none()
                }

                BackendEvent::WalletBestBlock(wallet_id, best_block) => {
                    self.node_state
                        .wallets
                        .get_mut(&wallet_id)
                        .expect("wallet must be known (BestBlock)")
                        .best_block = best_block;
                    Command::none()
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
                    Command::none()
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
                    Command::none()
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
                    Command::none()
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
                    Command::none()
                }
                BackendEvent::NewAddress(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
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
                    Command::none()
                }
                BackendEvent::ToggleStaking(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
                BackendEvent::SendAmount(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::SendSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Command::none()
                }
                BackendEvent::SendAmount(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
                BackendEvent::StakeAmount(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::CreateStakingPoolSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Command::none()
                }
                BackendEvent::StakeAmount(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
                BackendEvent::CreateDelegation(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::CreateDelegationSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Command::none()
                }
                BackendEvent::CreateDelegation(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
                BackendEvent::DelegateStaking(Ok((transaction_info, delegation_id))) => {
                    self.wallet_msg = Some(WalletMessage::DelegateStakingSucceed(delegation_id));
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Command::none()
                }
                BackendEvent::DelegateStaking(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
                BackendEvent::SendDelegationToAddress(Ok(transaction_info)) => {
                    self.wallet_msg = Some(WalletMessage::SendDelegationToAddressSucceed);
                    self.active_dialog = ActiveDialog::ConfirmTransaction { transaction_info };
                    Command::none()
                }
                BackendEvent::SendDelegationToAddress(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
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
                        Command::none()
                    }
                }
                BackendEvent::Broadcast(Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
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
                    Command::none()
                }
                BackendEvent::TransactionList(_wallet_id, _account_id, Err(error)) => {
                    self.show_error(error.to_string());
                    Command::none()
                }
            },
            MainWindowMessage::OpenWalletFileSelected { file_path } => {
                self.file_dialog_active = false;
                backend_sender.send(BackendRequest::OpenWallet { file_path });
                Command::none()
            }
            MainWindowMessage::OpenWalletFileCanceled => {
                self.file_dialog_active = false;
                Command::none()
            }

            MainWindowMessage::ImportWalletMnemonic { mnemonic, import } => {
                let mnemonic_res =
                    wallet_controller::mnemonic::parse_mnemonic(self.language, &mnemonic);
                match mnemonic_res {
                    Ok(mnemonic) => {
                        self.file_dialog_active = true;
                        Command::perform(
                            async move {
                                let file_opt = AsyncFileDialog::new().save_file().await;
                                if let Some(file) = file_opt {
                                    log::info!("Save wallet file: {file:?}");
                                    MainWindowMessage::ImportWalletFileSelected {
                                        mnemonic,
                                        file_path: file.path().to_owned(),
                                        import,
                                    }
                                } else {
                                    MainWindowMessage::ImportWalletFileCanceled
                                }
                            },
                            identity,
                        )
                    }
                    Err(err) => {
                        self.show_error(err.to_string());
                        Command::none()
                    }
                }
            }
            MainWindowMessage::ImportWalletFileSelected {
                mnemonic,
                file_path,
                import,
            } => {
                self.file_dialog_active = false;
                backend_sender.send(BackendRequest::RecoverWallet {
                    mnemonic,
                    file_path,
                    import,
                });
                Command::none()
            }
            MainWindowMessage::ImportWalletFileCanceled => {
                self.file_dialog_active = false;
                self.active_dialog = ActiveDialog::None;
                Command::none()
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
                Command::none()
            }

            MainWindowMessage::WalletUnlock {
                wallet_id,
                password,
            } => {
                backend_sender.send(BackendRequest::UpdateEncryption {
                    wallet_id,
                    action: EncryptionAction::Unlock(password),
                });
                Command::none()
            }

            MainWindowMessage::NewWalletAccount { wallet_id, name } => {
                backend_sender.send(BackendRequest::NewAccount { wallet_id, name });
                Command::none()
            }

            MainWindowMessage::SubmitTx { wallet_id, tx } => {
                backend_sender.send(BackendRequest::SubmitTx { wallet_id, tx });
                Command::none()
            }

            MainWindowMessage::CopyToClipboard(text) => iced::clipboard::write(text),

            MainWindowMessage::ClosePopup => {
                self.popups.pop();
                Command::none()
            }
            MainWindowMessage::CloseDialog => {
                self.active_dialog = ActiveDialog::None;
                Command::none()
            }
        }
    }

    pub fn view(&self) -> Element<MainWindowMessage> {
        let main_content = iced::widget::column![
            self.main_menu.view().map(MainWindowMessage::MenuMessage),
            self.main_widget
                .view(&self.node_state)
                .map(MainWindowMessage::MainWidgetMessage),
            // TODO: workaround for the tabview component not accounting for the tab labels height
            iced::widget::Column::new().height(70),
        ];

        let show_dialog = self.active_dialog != ActiveDialog::None;
        let dialog = show_dialog.then(move || -> Element<MainWindowMessage> {
            match &self.active_dialog {
                ActiveDialog::None => Text::new("Nothing to show").into(),

                ActiveDialog::WalletCreate { generated_mnemonic } => wallet_mnemonic_dialog(
                    Some(generated_mnemonic.clone()),
                    Box::new(|mnemonic| MainWindowMessage::ImportWalletMnemonic {
                        mnemonic,
                        import: ImportOrCreate::Create,
                    }),
                    Box::new(|| MainWindowMessage::CloseDialog),
                )
                .into(),

                ActiveDialog::WalletImport => wallet_mnemonic_dialog(
                    None,
                    Box::new(|mnemonic| MainWindowMessage::ImportWalletMnemonic {
                        mnemonic,
                        import: ImportOrCreate::Import,
                    }),
                    Box::new(|| MainWindowMessage::CloseDialog),
                )
                .into(),

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
        });

        // Always return Modal or iced will panic with "Downcast on stateless state" error

        let content_with_dialog =
            Modal::new(main_content, dialog).on_esc(MainWindowMessage::CloseDialog);

        let popup_opt = self.popups.last();
        let show_popup = popup_opt.is_some() || self.file_dialog_active;
        let popup = show_popup.then(move || -> Element<MainWindowMessage> {
            match (self.file_dialog_active, popup_opt) {
                (true, _) => Text::new("File dialog...").into(),
                (_, Some(popup)) => {
                    popup_dialog(popup.clone(), MainWindowMessage::ClosePopup).into()
                }
                (_, None) => Text::new("Nothing to show").into(),
            }
        });

        let popup_modal = Modal::new(content_with_dialog, popup);
        if self.file_dialog_active {
            popup_modal.into()
        } else {
            popup_modal.on_esc(MainWindowMessage::ClosePopup).into()
        }
    }
}
