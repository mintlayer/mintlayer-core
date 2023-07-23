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

use common::{chain::ChainConfig, primitives::Amount};
use iced::{
    widget::{
        button, column, container, horizontal_rule, pick_list, progress_bar, row, text, text_input,
        vertical_rule, Column, Row, Scrollable, Text,
    },
    Alignment, Command, Element, Length,
};
use iced_aw::{tab_bar::TabLabel, Grid};
use serialization::hex::HexEncode;
use wallet::account::Currency;
use wallet_controller::DEFAULT_ACCOUNT_INDEX;

use crate::{
    backend::{
        messages::{
            AccountId, AccountInfo, BackendRequest, EncryptionState, SendRequest, StakeRequest,
            WalletId, WalletInfo,
        },
        BackendSender,
    },
    main_window::{
        print_block_timestamp, print_coin_amount, print_coin_amount_with_name, NodeState,
    },
};

use super::{Tab, TabsMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPanel {
    Transactions,
    Addresses,
    Send,
    Stake,
}

#[derive(Debug, Clone)]
pub enum WalletMessage {
    CopyToClipboard(String),

    SelectPanel(SelectedPanel),

    SetPassword,
    RemovePassword,
    Lock,
    Unlock,

    NewAccount,
    SelectAccount(AccountId),

    GetNewAddress,
    SendAmountEdit(String),
    SendAddressEdit(String),
    Send,

    StakeAmountEdit(String),
    Stake,

    ToggleStaking(bool),

    TransactionList { skip: usize },

    Close,
}

/// State that should be reset after changing the selected account
#[derive(Default)]
pub struct AccountState {
    send_amount: String,
    send_address: String,
    stake_amount: String,
}

pub struct WalletTab {
    wallet_id: WalletId,
    selected_account: AccountId,
    selected_panel: SelectedPanel,
    account_state: AccountState,
}

impl WalletTab {
    pub fn new(wallet_id: WalletId) -> Self {
        WalletTab {
            wallet_id,
            selected_account: AccountId::new(DEFAULT_ACCOUNT_INDEX),
            selected_panel: SelectedPanel::Transactions,
            account_state: AccountState::default(),
        }
    }

    pub fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub fn update(
        &mut self,
        message: WalletMessage,
        backend_sender: &BackendSender,
    ) -> Command<WalletMessage> {
        match message {
            WalletMessage::CopyToClipboard(text) => {
                // TODO: Show toast notification
                iced::clipboard::write(text)
            }
            WalletMessage::SelectPanel(selected_panel) => {
                self.selected_panel = selected_panel;
                Command::none()
            }

            WalletMessage::SetPassword
            | WalletMessage::RemovePassword
            | WalletMessage::Lock
            | WalletMessage::Unlock => {
                // Processed by the main_window
                Command::none()
            }

            WalletMessage::NewAccount => {
                backend_sender.send(crate::backend::messages::BackendRequest::NewAccount {
                    wallet_id: self.wallet_id,
                    name: None,
                });
                Command::none()
            }
            WalletMessage::SelectAccount(account_id) => {
                if account_id != self.selected_account {
                    self.selected_account = account_id;
                    self.account_state = AccountState::default();
                }
                Command::none()
            }

            WalletMessage::GetNewAddress => {
                backend_sender.send(crate::backend::messages::BackendRequest::NewAddress(
                    self.wallet_id,
                    self.selected_account,
                ));
                Command::none()
            }
            WalletMessage::SendAmountEdit(value) => {
                self.account_state.send_amount = value;
                Command::none()
            }
            WalletMessage::SendAddressEdit(value) => {
                self.account_state.send_address = value;
                Command::none()
            }
            WalletMessage::Send => {
                let request = SendRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    address: self.account_state.send_address.clone(),
                    amount: self.account_state.send_amount.clone(),
                };
                backend_sender.send(BackendRequest::SendAmount(request));
                Command::none()
            }
            WalletMessage::StakeAmountEdit(value) => {
                self.account_state.stake_amount = value;
                Command::none()
            }
            WalletMessage::Stake => {
                let request = StakeRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    amount: self.account_state.stake_amount.clone(),
                };
                backend_sender.send(BackendRequest::StakeAmount(request));
                Command::none()
            }
            WalletMessage::ToggleStaking(enabled) => {
                backend_sender.send(BackendRequest::ToggleStaking(
                    self.wallet_id,
                    self.selected_account,
                    enabled,
                ));
                Command::none()
            }
            WalletMessage::TransactionList { skip } => {
                backend_sender.send(BackendRequest::TransactionList {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    skip,
                });
                Command::none()
            }
            WalletMessage::Close => {
                backend_sender.send(BackendRequest::CloseWallet(self.wallet_id));
                Command::none()
            }
        }
    }
}

#[allow(clippy::float_arithmetic)]
fn wallet_scan_progress(node_block_height: u64, wallet_block_height: u64) -> f32 {
    100.0 * wallet_block_height.min(node_block_height) as f32 / node_block_height.max(1) as f32
}

impl Tab for WalletTab {
    type Message = TabsMessage;

    fn title(&self) -> String {
        String::from("Wallet")
    }

    fn tab_label(&self) -> TabLabel {
        TabLabel::IconText(iced_aw::Icon::Wallet.into(), self.title())
    }

    fn content(&self, node_state: &NodeState) -> Element<Self::Message> {
        let wallet_info = match node_state.wallets.get(&self.wallet_id) {
            Some(wallet_info) => wallet_info,
            None => return Text::new("No wallet").into(),
        };

        let account = wallet_info
            .accounts
            .get(&self.selected_account)
            .expect("selected account must be known");

        let body = match self.selected_panel {
            SelectedPanel::Transactions => view_transactions(&node_state.chain_config, account),
            SelectedPanel::Addresses => view_addresses(account),
            SelectedPanel::Send => view_send(
                &self.account_state.send_address,
                &self.account_state.send_amount,
            ),
            SelectedPanel::Stake => view_stake(
                &node_state.chain_config,
                account,
                &self.account_state.stake_amount,
            ),
        };

        let body = Scrollable::new(container(body).padding(10))
            .width(Length::Fill)
            .height(Length::Fill);

        let top_panel = container(view_top_panel(
            &node_state.chain_config,
            wallet_info,
            account,
        ))
        .height(50)
        .width(Length::Fill);
        let left_panel = container(view_left_panel(
            node_state,
            wallet_info,
            self.selected_account,
            self.selected_panel,
        ))
        .width(150);

        let page: Element<'static, WalletMessage> = row![
            left_panel.width(Length::Fixed(150.0)),
            vertical_rule(1),
            column![top_panel, horizontal_rule(1.0), body]
        ]
        .width(Length::Fill)
        .into();

        page.map(|msg| TabsMessage::WalletMessage(self.wallet_id, msg))
    }
}

fn view_top_panel(
    chain_config: &ChainConfig,
    wallet_info: &WalletInfo,
    account: &AccountInfo,
) -> Element<'static, WalletMessage> {
    let balance = account.balance.get(&Currency::Coin).cloned().unwrap_or(Amount::ZERO);
    let balance = print_coin_amount_with_name(chain_config, balance);
    let balance = Text::new(balance).size(20);

    let password =
        match wallet_info.encryption {
            EncryptionState::EnabledLocked => {
                row![iced::widget::button(Text::new("Unlock")).on_press(WalletMessage::Unlock)]
            }
            EncryptionState::EnabledUnlocked => row![
                iced::widget::button(Text::new("Lock")).on_press(WalletMessage::Lock),
                iced::widget::button(Text::new("Disable wallet encryption"))
                    .on_press(WalletMessage::RemovePassword)
            ],
            EncryptionState::Disabled => row![iced::widget::button(Text::new("Encrypt wallet"))
                .on_press(WalletMessage::SetPassword),],
        }
        .align_items(Alignment::Center)
        .spacing(10);

    row![
        balance,
        Row::new().width(Length::Fill),
        password,
        button(Text::new("Close"))
            .style(iced::theme::Button::Destructive)
            .on_press(WalletMessage::Close),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(10)
    .padding(10)
    .align_items(Alignment::Center)
    .into()
}

#[derive(Clone, PartialEq, Eq)]
struct AccountPickItem {
    account_id: AccountId,
    name: String,
}

impl std::fmt::Display for AccountPickItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.name, f)
    }
}

fn view_left_panel(
    node_state: &NodeState,
    wallet_info: &WalletInfo,
    selected_account: AccountId,
    selected_panel: SelectedPanel,
) -> Element<'static, WalletMessage> {
    let file_name = wallet_info.path.file_name().map_or_else(
        || "<Unknown>".to_owned(),
        |file_name| file_name.to_string_lossy().to_string(),
    );

    let account_items = wallet_info
        .accounts
        .iter()
        .map(|(account_id, account)| AccountPickItem {
            name: account
                .name
                .clone()
                .unwrap_or_else(|| format!("Account {}", account_id.account_index())),
            account_id: *account_id,
        })
        .collect::<Vec<_>>();

    let selected_account = account_items
        .iter()
        .find(|account_item| account_item.account_id == selected_account)
        .cloned();
    let pick_list = pick_list(account_items, selected_account, |item| {
        WalletMessage::SelectAccount(item.account_id)
    });

    let panel_button = |label, panel, selected_panel| {
        let label = text(label).size(16);

        let button = button(label)
            .style(if panel == selected_panel {
                iced::theme::Button::Primary
            } else {
                iced::theme::Button::Text
            })
            .width(Length::Fill);

        button.on_press(WalletMessage::SelectPanel(panel)).padding(8)
    };

    // `next_height` is used to prevent flickering when a new block is found
    let show_scan_progress = wallet_info.best_block.1.next_height() < node_state.best_block_height;
    let scan_progress_widget = if show_scan_progress {
        // TODO: Fix scan progress when the node is in the initial block download state
        let scan_progress = wallet_scan_progress(
            node_state.best_block_height.into_int(),
            wallet_info.best_block.1.into_int(),
        );
        let scan_progress_str = format!(
            "{:.0}%\n({}/{} blocks)",
            scan_progress,
            wallet_info.best_block.1.into_int(),
            node_state.best_block_height.into_int()
        );
        column![
            text(scan_progress_str).horizontal_alignment(iced::alignment::Horizontal::Center),
            progress_bar(0.0..=100.0, scan_progress)
        ]
        .padding(10)
        .spacing(10)
        .align_items(Alignment::Center)
        .width(Length::Fill)
    } else {
        Column::new()
    };

    column![
        column![
            text(file_name).size(25),
            row![
                pick_list.width(100),
                button(Text::new("+"))
                    .style(iced::theme::Button::Positive)
                    .on_press(WalletMessage::NewAccount),
            ]
            .align_items(Alignment::Center)
            .spacing(10)
            .width(Length::Fill)
        ]
        .spacing(10)
        .padding(10),
        column![
            panel_button("Transactions", SelectedPanel::Transactions, selected_panel),
            panel_button("Addresses", SelectedPanel::Addresses, selected_panel),
            panel_button("Send", SelectedPanel::Send, selected_panel),
            panel_button("Stake", SelectedPanel::Stake, selected_panel),
        ]
        .height(Length::Fill),
        scan_progress_widget,
    ]
    .into()
}

fn view_addresses(account: &AccountInfo) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);
    let mut addresses = Grid::with_columns(3);
    for (index, address) in account.addresses.iter() {
        addresses = addresses
            .push(field(index.to_string()))
            .push(field(address.get().to_owned()))
            .push(
                button(
                    Text::new(iced_aw::Icon::ClipboardCheck.to_string()).font(iced_aw::ICON_FONT),
                )
                .style(iced::theme::Button::Text)
                .on_press(WalletMessage::CopyToClipboard(address.get().to_owned())),
            );
    }
    column![
        addresses,
        iced::widget::button(Text::new("New address")).on_press(WalletMessage::GetNewAddress)
    ]
    .into()
}

fn view_transactions(
    chain_config: &ChainConfig,
    account: &AccountInfo,
) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);
    let mut transactions = Column::new();

    let current_transaction_list = &account.transaction_list;
    let mut transaction_list = Grid::with_columns(5)
        .push("Num")
        .push("Txid")
        .push("Timestamp")
        .push("Type")
        .push("Amount");
    for (index, tx) in current_transaction_list.txs.iter().enumerate() {
        let amount_str = tx
            .tx_type
            .amount()
            .map(|amount| print_coin_amount(chain_config, amount))
            .unwrap_or_default();
        let timestamp = tx
            .block
            .as_ref()
            .and_then(|block| print_block_timestamp(block.timestamp))
            .unwrap_or_else(|| "-".to_owned());
        transaction_list = transaction_list
            .push(field(format!("{}", current_transaction_list.skip + index)))
            .push(field(tx.txid.to_string()))
            .push(field(timestamp))
            .push(field(tx.tx_type.type_name().to_owned()))
            .push(field(amount_str));
    }
    let transaction_list_controls = row![
        iced::widget::button(Text::new("<<")).on_press(WalletMessage::TransactionList {
            skip: current_transaction_list.skip.saturating_sub(current_transaction_list.count),
        }),
        Text::new(format!(
            "{}/{}",
            current_transaction_list.skip / current_transaction_list.count,
            current_transaction_list.total / current_transaction_list.count,
        )),
        iced::widget::button(Text::new(">>")).on_press(WalletMessage::TransactionList {
            skip: current_transaction_list.skip.saturating_add(current_transaction_list.count),
        }),
    ]
    .spacing(10)
    .align_items(Alignment::Center);
    transactions = transactions.push(transaction_list).push(transaction_list_controls);

    transactions.into()
}

fn view_send(send_address: &str, send_amount: &str) -> Element<'static, WalletMessage> {
    column![
        text_input("Address", send_address)
            .on_input(|value| { WalletMessage::SendAddressEdit(value) })
            .padding(15),
        text_input("Amount", send_amount)
            .on_input(|value| { WalletMessage::SendAmountEdit(value) })
            .padding(15),
        iced::widget::button(Text::new("Send")).on_press(WalletMessage::Send)
    ]
    .spacing(10)
    .into()
}

fn view_stake(
    chain_config: &ChainConfig,
    account: &AccountInfo,
    stake_amount: &str,
) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);

    let mut staking_balance_grid = Grid::with_columns(2)
        .push(field("PoolId".to_owned()))
        .push(field("Balance".to_owned()));
    for (pool_id, balance) in account.staking_balance.iter() {
        staking_balance_grid = staking_balance_grid
            .push(field(pool_id.hex_encode()))
            .push(field(print_coin_amount(chain_config, *balance)));
    }
    if account.staking_balance.is_empty() {
        staking_balance_grid = staking_balance_grid
            .push(field("No staking pools found".to_owned()))
            .push(field(String::new()));
    }

    let (staking_status, staking_button, new_state) = if account.staking_enabled {
        ("Staking started", "Stop", false)
    } else {
        ("Staking stopped", "Start", true)
    };

    column![
        row![
            Text::new(staking_status),
            iced::widget::button(Text::new(staking_button))
                .on_press(WalletMessage::ToggleStaking(new_state))
        ]
        .spacing(10)
        .align_items(Alignment::Center),
        staking_balance_grid,
        text_input("Stake amount", stake_amount)
            .on_input(|value| { WalletMessage::StakeAmountEdit(value) })
            .padding(15),
        iced::widget::button(Text::new("Stake")).on_press(WalletMessage::Stake),
    ]
    .spacing(10)
    .into()
}
