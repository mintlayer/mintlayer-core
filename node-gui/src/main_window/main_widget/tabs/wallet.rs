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

use std::fmt::Debug;

use common::{chain::ChainConfig, primitives::Amount};
use iced::{
    widget::{button, column, container, progress_bar, row, text, text_input, Column, Text},
    Command, Element, Length,
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
    main_window::{print_block_timestamp, print_coin_amount, NodeState},
};

use super::{Tab, TabsMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPanel {
    Balance,
    Addresses,
    Transactions,
    Send,
    Stake,
}

#[derive(Debug, Clone)]
pub enum WalletMessage {
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

pub struct WalletTab {
    wallet_id: WalletId,
    selected_account: AccountId,
    send_amount: String,
    send_address: String,
    stake_amount: String,
    selected_panel: SelectedPanel,
}

impl WalletTab {
    pub fn new(wallet_id: WalletId) -> Self {
        WalletTab {
            wallet_id,
            selected_account: AccountId::new(DEFAULT_ACCOUNT_INDEX),
            send_amount: String::new(),
            send_address: String::new(),
            stake_amount: String::new(),
            selected_panel: SelectedPanel::Balance,
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
                self.send_amount = value;
                Command::none()
            }
            WalletMessage::SendAddressEdit(value) => {
                self.send_address = value;
                Command::none()
            }
            WalletMessage::Send => {
                let request = SendRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    address: self.send_address.clone(),
                    amount: self.send_amount.clone(),
                };
                backend_sender.send(BackendRequest::SendAmount(request));
                Command::none()
            }
            WalletMessage::StakeAmountEdit(value) => {
                self.stake_amount = value;
                Command::none()
            }
            WalletMessage::Stake => {
                let request = StakeRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    amount: self.stake_amount.clone(),
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
    wallet_block_height.min(node_block_height) as f32 / node_block_height.max(1) as f32
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

        // TODO: Fix scan progress when the node is in the initial block download state
        let scan_progress = wallet_scan_progress(
            node_state.best_block_height.into_int(),
            wallet_info.best_block.1.into_int(),
        );

        let body = match self.selected_panel {
            SelectedPanel::Balance => view_balance(&node_state.chain_config, account),
            SelectedPanel::Addresses => view_addresses(account),
            SelectedPanel::Transactions => view_transactions(&node_state.chain_config, account),
            SelectedPanel::Send => view_send(&self.send_address, &self.send_amount),
            SelectedPanel::Stake => {
                view_stake(&node_state.chain_config, account, &self.stake_amount)
            }
        };

        let top_panel = container(view_top_pannel(wallet_info)).height(100).width(Length::Fill);
        let left_panel = container(view_left_pannel(self.selected_panel, scan_progress)).width(150);

        let page: Element<'static, WalletMessage> =
            column![top_panel, row![left_panel, body].width(Length::Fill)].into();

        page.map(|msg| TabsMessage::WalletMessage(self.wallet_id, msg))
    }
}

fn view_top_pannel(wallet_info: &WalletInfo) -> Element<'static, WalletMessage> {
    let file_name = wallet_info.path.file_name().map_or_else(
        || "<Unknown>".to_owned(),
        |file_name| file_name.to_string_lossy().to_string(),
    );

    let encryption_state = match wallet_info.encryption {
        EncryptionState::EnabledLocked => "Locked",
        EncryptionState::EnabledUnlocked => "Unlocked",
        EncryptionState::Disabled => "Disabled",
    };

    row![
        column![
            text(file_name).size(20),
            iced::widget::button(Text::new("Close")).on_press(WalletMessage::Close)
        ]
        .width(Length::FillPortion(1)),
        column![iced::widget::button(Text::new("New Account")).on_press(
            WalletMessage::NewAccount,
        )]
        .width(Length::FillPortion(1)),
        column![text(encryption_state).size(16)].width(Length::FillPortion(1)),
    ]
    .width(Length::Fill)
    .into()
}

fn view_left_pannel(
    selected_panel: SelectedPanel,
    scan_progress: f32,
) -> Element<'static, WalletMessage> {
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

    column![
        column![
            panel_button("Balance", SelectedPanel::Balance, selected_panel),
            panel_button("Addresses", SelectedPanel::Addresses, selected_panel),
            panel_button("Transactions", SelectedPanel::Transactions, selected_panel),
            panel_button("Send", SelectedPanel::Send, selected_panel),
            panel_button("Stake", SelectedPanel::Stake, selected_panel),
        ]
        .height(Length::Fill),
        container(progress_bar(0.0..=1.0, scan_progress))
            .width(Length::Fill)
            .padding(10),
    ]
    .into()
}

fn view_balance(
    chain_config: &ChainConfig,
    account: &AccountInfo,
) -> Element<'static, WalletMessage> {
    let balance = account.balance.get(&Currency::Coin).cloned().unwrap_or(Amount::ZERO);
    let balance_str = print_coin_amount(chain_config, balance);
    Text::new(balance_str).into()
}

fn view_addresses(account: &AccountInfo) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);
    let mut addresses = Grid::with_columns(2);
    for (index, address) in account.addresses.iter() {
        addresses = addresses.push(field(index.to_string())).push(field(address.get().to_owned()));
    }
    addresses.into()
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
    ];
    transactions = transactions.push(transaction_list).push(transaction_list_controls);

    transactions.into()
}

fn view_send(send_address: &str, send_amount: &str) -> Element<'static, WalletMessage> {
    row![
        text_input("Address", send_address)
            .on_input(|value| { WalletMessage::SendAddressEdit(value) })
            .padding(15),
        text_input("Amount", &send_amount)
            .on_input(|value| { WalletMessage::SendAmountEdit(value) })
            .padding(15),
        iced::widget::button(Text::new("Send")).on_press(WalletMessage::Send)
    ]
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
    let (staking_status, staking_button, new_state) = if account.staking_enabled {
        ("Staking started", "Stop", false)
    } else {
        ("Staking stopped", "Start", true)
    };
    staking_balance_grid = staking_balance_grid.push(Text::new(staking_status)).push(
        iced::widget::button(Text::new(staking_button))
            .on_press(WalletMessage::ToggleStaking(new_state)),
    );
    column![
        staking_balance_grid,
        row![
            text_input("Stake amount", &stake_amount)
                .on_input(|value| { WalletMessage::StakeAmountEdit(value) })
                .padding(15),
            iced::widget::button(Text::new("Stake")).on_press(WalletMessage::Stake)
        ]
    ]
    .into()
}
