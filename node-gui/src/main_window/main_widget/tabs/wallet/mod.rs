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
mod console;
mod delegation;
mod left_panel;
mod send;
mod stake;
mod top_panel;
mod transactions;

use std::collections::BTreeMap;

use common::chain::DelegationId;
pub use console::CONSOLE_OUTPUT_ID;
use iced::{
    widget::{
        column, container, horizontal_rule, pane_grid, row,
        scrollable::{snap_to, Id},
        vertical_rule, PaneGrid, Scrollable, Text,
    },
    Command, Element, Length,
};
use iced_aw::tab_bar::TabLabel;
use wallet_controller::DEFAULT_ACCOUNT_INDEX;
use wallet_types::wallet_type::WalletType;

use crate::{
    backend::{
        messages::{
            AccountId, BackendRequest, CreateDelegationRequest, DecommissionPoolRequest,
            DelegateStakingRequest, SendDelegateToAddressRequest, SendRequest, StakeRequest,
            WalletId,
        },
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
    Delegation,
    Console,
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
    SendSucceed,

    StakeAmountEdit(String),
    MarginPerThousandEdit(String),
    CostPerBlockEdit(String),
    DecommissionAddressEdit(String),
    CreateStakingPool,
    CreateStakingPoolSucceed,

    DecommissionPoolIdEdit(String),
    DecommissionPoolAddressEdit(String),
    DecommissionPool,
    DecommissionPoolSucceed,

    DelegationPoolIdEdit(String),
    DelegationAddressEdit(String),
    CreateDelegation,
    CreateDelegationSucceed,
    SendDelegationAddressEdit(String),
    SendDelegationAmountEdit(String),
    SendDelegationIdEdit(String),
    SendDelegationToAddress,
    SendDelegationToAddressSucceed,
    DelegateStaking(DelegationId),
    DelegationAmountEdit((DelegationId, String)),
    DelegateStakingSucceed(DelegationId),

    ToggleStaking(bool),

    TransactionList { skip: usize },

    ConsoleInputChange(String),
    ConsoleInputSubmit,

    StillSyncing,
    Close,
    NoOp,
}

#[derive(Debug, Clone, Default)]
pub struct ConsoleState {
    pub console_outputs: Vec<String>,
    pub console_input: String,
}

/// State that should be reset after changing the selected account
#[derive(Default)]
pub struct AccountState {
    send_amount: String,
    send_address: String,
    stake_amount: String,
    margin_per_thousand: String,
    cost_per_block_amount: String,
    decommission_address: String,

    decommission_pool_address: String,
    decommission_pool_id: String,

    delegation_pool_id: String,
    delegation_address: String,
    delegate_staking_amounts: BTreeMap<DelegationId, String>,

    send_delegation_address: String,
    send_delegation_amount: String,
    send_delegation_id: String,

    console_state: ConsoleState,
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
    pub fn new(wallet_id: WalletId, wallet_type: WalletType) -> Self {
        let (mut panes, pane) = pane_grid::State::new(WalletPane::Left);

        let (_pane, split) = panes
            .split(pane_grid::Axis::Vertical, pane, WalletPane::Right)
            .expect("split should not fail");
        panes.resize(split, 0.2);

        let selected_panel = match wallet_type {
            WalletType::Hot => SelectedPanel::Transactions,
            WalletType::Cold => SelectedPanel::Addresses,
        };

        WalletTab {
            wallet_id,
            selected_account: AccountId::new(DEFAULT_ACCOUNT_INDEX),
            selected_panel,
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
                if self.selected_panel == SelectedPanel::Console {
                    snap_to(
                        Id::new(CONSOLE_OUTPUT_ID),
                        iced::widget::scrollable::RelativeOffset { x: 0.0, y: 1.0 },
                    )
                } else {
                    Command::none()
                }
            }

            WalletMessage::Resized(pane_grid::ResizeEvent { split, ratio }) => {
                self.panes.resize(split, ratio);
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
            WalletMessage::SendSucceed => {
                self.account_state.send_address.clear();
                self.account_state.send_amount.clear();
                Command::none()
            }
            WalletMessage::StakeAmountEdit(value) => {
                self.account_state.stake_amount = value;
                Command::none()
            }
            WalletMessage::MarginPerThousandEdit(value) => {
                self.account_state.margin_per_thousand = value;
                Command::none()
            }
            WalletMessage::CostPerBlockEdit(value) => {
                self.account_state.cost_per_block_amount = value;
                Command::none()
            }
            WalletMessage::DecommissionAddressEdit(value) => {
                self.account_state.decommission_address = value;
                Command::none()
            }
            WalletMessage::DecommissionPoolIdEdit(value) => {
                self.account_state.decommission_pool_id = value;
                Command::none()
            }
            WalletMessage::DecommissionPoolAddressEdit(value) => {
                self.account_state.decommission_pool_address = value;
                Command::none()
            }

            WalletMessage::CreateStakingPool => {
                let request = StakeRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    pledge_amount: self.account_state.stake_amount.clone(),
                    mpt: self.account_state.margin_per_thousand.clone(),
                    cost_per_block: self.account_state.cost_per_block_amount.clone(),
                    decommission_address: self.account_state.decommission_address.clone(),
                };
                backend_sender.send(BackendRequest::StakeAmount(request));
                Command::none()
            }
            WalletMessage::CreateStakingPoolSucceed => {
                self.account_state.stake_amount.clear();
                self.account_state.margin_per_thousand.clear();
                self.account_state.cost_per_block_amount.clear();
                self.account_state.decommission_address.clear();
                Command::none()
            }
            WalletMessage::DecommissionPool => {
                let request = DecommissionPoolRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    pool_id: self.account_state.decommission_pool_id.clone(),
                    output_address: self.account_state.decommission_pool_address.clone(),
                };
                backend_sender.send(BackendRequest::DecommissionPool(request));
                Command::none()
            }
            WalletMessage::DecommissionPoolSucceed => {
                self.account_state.decommission_pool_id.clear();
                self.account_state.decommission_pool_address.clear();
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
            WalletMessage::ConsoleInputChange(new_state) => {
                self.account_state.console_state.console_input = new_state;
                Command::none()
            }
            WalletMessage::ConsoleInputSubmit => {
                self.account_state
                    .console_state
                    .console_outputs
                    .push(self.account_state.console_state.console_input.clone());
                backend_sender.send(BackendRequest::ConsoleCommand {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    command: std::mem::take(&mut self.account_state.console_state.console_input),
                });
                Command::none()
            }
            WalletMessage::StillSyncing => Command::none(),
            WalletMessage::Close => {
                backend_sender.send(BackendRequest::CloseWallet(self.wallet_id));
                Command::none()
            }
            WalletMessage::DelegationPoolIdEdit(value) => {
                self.account_state.delegation_pool_id = value;
                Command::none()
            }
            WalletMessage::DelegationAddressEdit(value) => {
                self.account_state.delegation_address = value;
                Command::none()
            }
            WalletMessage::CreateDelegation => {
                let request = CreateDelegationRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    pool_id: self.account_state.delegation_pool_id.clone(),
                    delegation_address: self.account_state.delegation_address.clone(),
                };
                backend_sender.send(BackendRequest::CreateDelegation(request));
                Command::none()
            }
            WalletMessage::CreateDelegationSucceed => {
                self.account_state.delegation_pool_id.clear();
                self.account_state.delegation_address.clear();
                Command::none()
            }
            WalletMessage::DelegateStaking(delegation_id) => {
                let request = DelegateStakingRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    delegation_id,
                    delegation_amount: self
                        .account_state
                        .delegate_staking_amounts
                        .get(&delegation_id)
                        .cloned()
                        .unwrap_or(String::new()),
                };
                backend_sender.send(BackendRequest::DelegateStaking(request));
                Command::none()
            }
            WalletMessage::DelegationAmountEdit((delegation_id, amount)) => {
                self.account_state.delegate_staking_amounts.insert(delegation_id, amount);
                Command::none()
            }
            WalletMessage::DelegateStakingSucceed(delegation_id) => {
                self.account_state.delegate_staking_amounts.remove(&delegation_id);
                Command::none()
            }
            WalletMessage::SendDelegationAddressEdit(value) => {
                self.account_state.send_delegation_address = value;
                Command::none()
            }
            WalletMessage::SendDelegationAmountEdit(value) => {
                self.account_state.send_delegation_amount = value;
                Command::none()
            }
            WalletMessage::SendDelegationIdEdit(value) => {
                self.account_state.send_delegation_id = value;
                Command::none()
            }
            WalletMessage::SendDelegationToAddress => {
                let request = SendDelegateToAddressRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    address: self.account_state.send_delegation_address.clone(),
                    amount: self.account_state.send_delegation_amount.clone(),
                    delegation_id: self.account_state.send_delegation_id.clone(),
                };
                backend_sender.send(BackendRequest::SendDelegationToAddress(request));
                Command::none()
            }
            WalletMessage::SendDelegationToAddressSucceed => {
                self.account_state.send_delegation_address.clear();
                self.account_state.send_delegation_amount.clear();
                self.account_state.send_delegation_id.clear();
                Command::none()
            }
            WalletMessage::NoOp => Command::none(),
        }
    }
}

impl Tab for WalletTab {
    type Message = TabsMessage;

    fn title(&self) -> String {
        String::from("Wallet")
    }

    fn tab_label(&self) -> TabLabel {
        TabLabel::IconText(iced_aw::BootstrapIcon::Wallet.into(), self.title())
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

        let still_syncing = match wallet_info.wallet_type {
            WalletType::Cold => false,
            WalletType::Hot => {
                wallet_info.best_block.1.next_height() < node_state.chain_info.best_block_height
            }
        }
        .then_some(WalletMessage::StillSyncing);

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
                        SelectedPanel::Addresses => {
                            addresses::view_addresses(account, still_syncing.clone())
                        }
                        SelectedPanel::Send => send::view_send(
                            &self.account_state.send_address,
                            &self.account_state.send_amount,
                            still_syncing.clone(),
                        ),
                        SelectedPanel::Staking => stake::view_stake(
                            &node_state.chain_config,
                            account,
                            &self.account_state.stake_amount,
                            &self.account_state.margin_per_thousand,
                            &self.account_state.cost_per_block_amount,
                            &self.account_state.decommission_address,
                            &self.account_state.decommission_pool_id,
                            &self.account_state.decommission_pool_address,
                            still_syncing.clone(),
                        ),
                        SelectedPanel::Delegation => delegation::view_delegation(
                            &node_state.chain_config,
                            account,
                            &self.account_state.delegation_pool_id,
                            &self.account_state.delegation_address,
                            &self.account_state.send_delegation_address,
                            &self.account_state.send_delegation_amount,
                            &self.account_state.send_delegation_id,
                            &self.account_state.delegate_staking_amounts,
                            still_syncing.clone(),
                        ),
                        SelectedPanel::Console => console::view_console(
                            &self.account_state.console_state,
                            &node_state
                                .wallets
                                .get(&self.wallet_id)
                                .expect("exists")
                                .accounts
                                .get(&self.selected_account)
                                .expect("exists")
                                .console_outputs,
                            still_syncing.clone(),
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
