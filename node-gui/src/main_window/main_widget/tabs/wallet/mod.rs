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

mod addresses;
mod left_panel;
mod send;
mod stake;
mod top_panel;
mod transactions;

use iced::{
    widget::{
        column, container, horizontal_rule, pane_grid, row, vertical_rule, PaneGrid, Scrollable,
        Text,
    },
    Command, Element, Length,
};
use iced_aw::tab_bar::TabLabel;
use wallet_controller::DEFAULT_ACCOUNT_INDEX;

use crate::{
    backend::{
        messages::{AccountId, BackendRequest, SendRequest, StakeRequest, WalletId},
        BackendSender,
    },
    main_window::NodeState,
};

use super::{Tab, TabsMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPanel {
    Transactions,
    Addresses,
    Send,
    Staking,
}

#[derive(Debug, Clone)]
pub enum WalletMessage {
    CopyToClipboard(String),

    SelectPanel(SelectedPanel),
    Resized(pane_grid::ResizeEvent),

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
    CreateStakingPool,

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
    panes: pane_grid::State<WalletPane>,
}

enum WalletPane {
    Left,
    Right,
}

impl WalletTab {
    pub fn new(wallet_id: WalletId) -> Self {
        let (mut panes, pane) = pane_grid::State::new(WalletPane::Left);

        let (_pane, split) = panes
            .split(pane_grid::Axis::Vertical, &pane, WalletPane::Right)
            .expect("split should not fail");
        panes.resize(&split, 0.2);

        WalletTab {
            wallet_id,
            selected_account: AccountId::new(DEFAULT_ACCOUNT_INDEX),
            selected_panel: SelectedPanel::Transactions,
            account_state: AccountState::default(),
            panes,
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

            WalletMessage::Resized(pane_grid::ResizeEvent { split, ratio }) => {
                self.panes.resize(&split, ratio);
                Command::none()
            }

            WalletMessage::SetPassword
            | WalletMessage::RemovePassword
            | WalletMessage::Lock
            | WalletMessage::Unlock
            | WalletMessage::NewAccount => {
                // Processed by the main_window
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
            WalletMessage::CreateStakingPool => {
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

        // PaneGrid is used to make the left panel resizable
        let pane_grid: Element<WalletMessage> =
            PaneGrid::new(&self.panes, move |_id, pane, _is_maximized| match pane {
                WalletPane::Left => {
                    let left_panel = left_panel::view_left_panel(
                        node_state,
                        wallet_info,
                        self.selected_account,
                        self.selected_panel,
                    );

                    pane_grid::Content::new(row![left_panel, vertical_rule(1)])
                }
                WalletPane::Right => {
                    let body = match self.selected_panel {
                        SelectedPanel::Transactions => {
                            transactions::view_transactions(&node_state.chain_config, account)
                        }
                        SelectedPanel::Addresses => addresses::view_addresses(account),
                        SelectedPanel::Send => send::view_send(
                            &self.account_state.send_address,
                            &self.account_state.send_amount,
                        ),
                        SelectedPanel::Staking => stake::view_stake(
                            &node_state.chain_config,
                            account,
                            &self.account_state.stake_amount,
                        ),
                    };

                    let body = Scrollable::new(container(body).padding(10))
                        .width(Length::Fill)
                        .height(Length::Fill);

                    let top_panel = container(top_panel::view_top_panel(
                        &node_state.chain_config,
                        wallet_info,
                        account,
                    ))
                    .height(50)
                    .width(Length::Fill);

                    pane_grid::Content::new(column![top_panel, horizontal_rule(1.0), body])
                }
            })
            .width(Length::Fill)
            .height(Length::Fill)
            .on_resize(10, WalletMessage::Resized)
            .into();

        pane_grid.map(|msg| TabsMessage::WalletMessage(self.wallet_id, msg))
    }
}
