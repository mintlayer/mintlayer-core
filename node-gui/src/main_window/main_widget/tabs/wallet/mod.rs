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
mod delegation;
mod left_panel;
mod send;
mod stake;
mod status_bar;
mod top_panel;
mod transactions;

mod console;
pub use console::CONSOLE_OUTPUT_ID;

use std::collections::BTreeMap;

use iced::{
    widget::{
        column, container, horizontal_rule, pane_grid, row,
        scrollable::{snap_to, Id},
        vertical_rule, PaneGrid, Scrollable, Text,
    },
    Element, Length, Task,
};
use iced_aw::tab_bar::TabLabel;

use common::chain::DelegationId;
use node_gui_backend::{
    messages::{
        BackendRequest, CreateDelegationRequest, DecommissionPoolRequest, DelegateStakingRequest,
        SendDelegateToAddressRequest, SendRequest, StakeRequest, WalletId,
    },
    AccountId, BackendSender,
};
use wallet_controller::DEFAULT_ACCOUNT_INDEX;
use wallet_types::wallet_type::WalletType;

use crate::main_window::NodeState;

use super::{Tab, TabsMessage};

pub const STATUS_BAR_SEPARATOR_HEIGHT: f32 = 1.0;

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
    ConsoleOutput(String),
    ConsoleClear,

    StillSyncing,
    Close,
    NoOp,
}

#[derive(Debug, Clone, Default)]
pub struct ConsoleState {
    pub console_inputs: Vec<String>,
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
            #[cfg(feature = "trezor")]
            WalletType::Trezor => SelectedPanel::Transactions,
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
    ) -> Task<WalletMessage> {
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
                    Task::none()
                }
            }

            WalletMessage::Resized(pane_grid::ResizeEvent { split, ratio }) => {
                self.panes.resize(split, ratio);
                Task::none()
            }

            WalletMessage::SetPassword
            | WalletMessage::RemovePassword
            | WalletMessage::Lock
            | WalletMessage::Unlock
            | WalletMessage::NewAccount => {
                // Processed by the main_window
                Task::none()
            }

            WalletMessage::SelectAccount(account_id) => {
                if account_id != self.selected_account {
                    self.selected_account = account_id;
                    self.account_state = AccountState::default();
                }
                Task::none()
            }

            WalletMessage::GetNewAddress => {
                backend_sender.send(BackendRequest::NewAddress(
                    self.wallet_id,
                    self.selected_account,
                ));
                Task::none()
            }
            WalletMessage::SendAmountEdit(value) => {
                self.account_state.send_amount = value;
                Task::none()
            }
            WalletMessage::SendAddressEdit(value) => {
                self.account_state.send_address = value;
                Task::none()
            }
            WalletMessage::Send => {
                let request = SendRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    address: self.account_state.send_address.clone(),
                    amount: self.account_state.send_amount.clone(),
                };
                backend_sender.send(BackendRequest::SendAmount(request));
                Task::none()
            }
            WalletMessage::SendSucceed => {
                self.account_state.send_address.clear();
                self.account_state.send_amount.clear();
                Task::none()
            }
            WalletMessage::StakeAmountEdit(value) => {
                self.account_state.stake_amount = value;
                Task::none()
            }
            WalletMessage::MarginPerThousandEdit(value) => {
                self.account_state.margin_per_thousand = value;
                Task::none()
            }
            WalletMessage::CostPerBlockEdit(value) => {
                self.account_state.cost_per_block_amount = value;
                Task::none()
            }
            WalletMessage::DecommissionAddressEdit(value) => {
                self.account_state.decommission_address = value;
                Task::none()
            }
            WalletMessage::DecommissionPoolIdEdit(value) => {
                self.account_state.decommission_pool_id = value;
                Task::none()
            }
            WalletMessage::DecommissionPoolAddressEdit(value) => {
                self.account_state.decommission_pool_address = value;
                Task::none()
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
                Task::none()
            }
            WalletMessage::CreateStakingPoolSucceed => {
                self.account_state.stake_amount.clear();
                self.account_state.margin_per_thousand.clear();
                self.account_state.cost_per_block_amount.clear();
                self.account_state.decommission_address.clear();
                Task::none()
            }
            WalletMessage::DecommissionPool => {
                let request = DecommissionPoolRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    pool_id: self.account_state.decommission_pool_id.clone(),
                    output_address: self.account_state.decommission_pool_address.clone(),
                };
                backend_sender.send(BackendRequest::DecommissionPool(request));
                Task::none()
            }
            WalletMessage::DecommissionPoolSucceed => {
                self.account_state.decommission_pool_id.clear();
                self.account_state.decommission_pool_address.clear();
                Task::none()
            }
            WalletMessage::ToggleStaking(enabled) => {
                backend_sender.send(BackendRequest::ToggleStaking(
                    self.wallet_id,
                    self.selected_account,
                    enabled,
                ));
                Task::none()
            }
            WalletMessage::TransactionList { skip } => {
                backend_sender.send(BackendRequest::TransactionList {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    skip,
                });
                Task::none()
            }
            WalletMessage::ConsoleInputChange(new_state) => {
                self.account_state.console_state.console_input = new_state;
                Task::none()
            }
            WalletMessage::ConsoleInputSubmit => {
                self.account_state
                    .console_state
                    .console_inputs
                    .push(self.account_state.console_state.console_input.clone());
                backend_sender.send(BackendRequest::ConsoleCommand {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    command: std::mem::take(&mut self.account_state.console_state.console_input),
                });
                Task::none()
            }
            WalletMessage::ConsoleClear => {
                self.account_state.console_state.console_outputs.clear();
                self.account_state.console_state.console_inputs.clear();

                Task::none()
            }
            WalletMessage::ConsoleOutput(output) => {
                self.account_state.console_state.console_outputs.push(output);

                snap_to(
                    Id::new(CONSOLE_OUTPUT_ID),
                    iced::widget::scrollable::RelativeOffset { x: 0.0, y: 1.0 },
                )
            }
            WalletMessage::StillSyncing => Task::none(),
            WalletMessage::Close => {
                backend_sender.send(BackendRequest::CloseWallet(self.wallet_id));
                Task::none()
            }
            WalletMessage::DelegationPoolIdEdit(value) => {
                self.account_state.delegation_pool_id = value;
                Task::none()
            }
            WalletMessage::DelegationAddressEdit(value) => {
                self.account_state.delegation_address = value;
                Task::none()
            }
            WalletMessage::CreateDelegation => {
                let request = CreateDelegationRequest {
                    wallet_id: self.wallet_id,
                    account_id: self.selected_account,
                    pool_id: self.account_state.delegation_pool_id.clone(),
                    delegation_address: self.account_state.delegation_address.clone(),
                };
                backend_sender.send(BackendRequest::CreateDelegation(request));
                Task::none()
            }
            WalletMessage::CreateDelegationSucceed => {
                self.account_state.delegation_pool_id.clear();
                self.account_state.delegation_address.clear();
                Task::none()
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
                Task::none()
            }
            WalletMessage::DelegationAmountEdit((delegation_id, amount)) => {
                self.account_state.delegate_staking_amounts.insert(delegation_id, amount);
                Task::none()
            }
            WalletMessage::DelegateStakingSucceed(delegation_id) => {
                self.account_state.delegate_staking_amounts.remove(&delegation_id);
                Task::none()
            }
            WalletMessage::SendDelegationAddressEdit(value) => {
                self.account_state.send_delegation_address = value;
                Task::none()
            }
            WalletMessage::SendDelegationAmountEdit(value) => {
                self.account_state.send_delegation_amount = value;
                Task::none()
            }
            WalletMessage::SendDelegationIdEdit(value) => {
                self.account_state.send_delegation_id = value;
                Task::none()
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
                Task::none()
            }
            WalletMessage::SendDelegationToAddressSucceed => {
                self.account_state.send_delegation_address.clear();
                self.account_state.send_delegation_amount.clear();
                self.account_state.send_delegation_id.clear();
                Task::none()
            }
            WalletMessage::NoOp => Task::none(),
        }
    }
}

impl Tab for WalletTab {
    type Message = TabsMessage;

    fn tab_label(&self, node_state: &NodeState) -> TabLabel {
        let text = match node_state.wallets.get(&self.wallet_id) {
            Some(wallet_info) => match wallet_info.extra_info {
                wallet_controller::types::WalletExtraInfo::SoftwareWallet => "Software wallet",
                wallet_controller::types::WalletExtraInfo::TrezorWallet { .. } => "Trezor wallet",
            },
            None => "No wallet",
        };

        TabLabel::IconText(iced_fonts::Bootstrap::Wallet.into(), text.to_owned())
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
            #[cfg(feature = "trezor")]
            WalletType::Trezor => {
                wallet_info.best_block.1.next_height() < node_state.chain_info.best_block_height
            }
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
                            still_syncing.clone(),
                            wallet_info,
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

        let result = if let Some(status_bar) = status_bar::view_status_bar(&wallet_info.extra_info)
        {
            Element::new(column![
                pane_grid,
                horizontal_rule(STATUS_BAR_SEPARATOR_HEIGHT),
                container(status_bar).width(Length::Fill)
            ])
        } else {
            pane_grid
        };

        result.map(|msg| TabsMessage::WalletMessage(self.wallet_id, msg))
    }
}
