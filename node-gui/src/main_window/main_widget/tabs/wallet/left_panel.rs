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

use iced::{
    widget::{button, column, pick_list, progress_bar, row, text, tooltip, Column, Text},
    Alignment, Element, Length,
};

use node_gui_backend::{messages::WalletInfo, AccountId};
use wallet_types::wallet_type::WalletType;

use crate::main_window::NodeState;

use super::{SelectedPanel, WalletMessage};

const TRANSACTIONS_TOOLTIP_TEXT: &str =
    "List of all transactions related to this account in the wallet.";
const ADDRESSES_TOOLTIP_TEXT: &str = "List all the addresses generated in this account in the wallet. \
    Addresses can be used for various purposes, such as destinations for coins sent to you, and also as an indicator to who is allowed to decommission a staking pool.";
const SEND_TOOLTIP_TEXT: &str = "Send coins to another address.";
const STAKING_TOOLTIP_TEXT: &str = "Staking is the process of assisting the network in generating blocks. \
    If you have the minimum amount of required coins for staking, you can participate by creating a pool, staking, \
    and earn rewards for it. Your node will be required to be left running.";
const DELEGATION_TOOLTIP_TEXT: &str = "Delegation is part of staking, where if you do not own the minimum required amount to stake, \
    you can delegate your coins to a pool to do the staking for you. The staking pool earns a cut of your rewards, \
    and you won't have to keep your node running.";
const CONSOLE_TOOLTIP_TEXT: &str = "Console for using low-level functions of the wallet.";

const NEW_ACCOUNT_TOOLTIP_TEXT: &str =
    "Accounts provide a way to completely separate keys and operations. \
    For example, you can have an account for personal use, and an account for work. \
    Each account will have a completely different set of keys.";

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

#[allow(clippy::float_arithmetic)]
fn wallet_scan_progress(node_block_height: u64, wallet_block_height: u64) -> f32 {
    100.0 * wallet_block_height.min(node_block_height) as f32 / node_block_height.max(1) as f32
}

pub fn view_left_panel(
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

    let panel_button = |label, panel, selected_panel, tooltip_text| {
        let label = row![
            text(label).size(16).width(Length::Fill),
            tooltip(
                Text::new(iced_fonts::Bootstrap::Question.to_string())
                    .font(iced_fonts::BOOTSTRAP_FONT),
                tooltip_text,
                tooltip::Position::Bottom
            )
            .gap(10)
            .style(iced::widget::container::bordered_box),
        ];

        button(label)
            .style(if panel == selected_panel {
                iced::widget::button::primary
            } else {
                iced::widget::button::text
            })
            .width(Length::Fill)
            .on_press(WalletMessage::SelectPanel(panel))
            .padding(8)
    };

    // `next_height` is used to prevent flickering when a new block is found
    let show_scan_progress = match wallet_info.wallet_type {
        WalletType::Cold => false,
        #[cfg(feature = "trezor")]
        WalletType::Trezor => {
            wallet_info.best_block.1.next_height() < node_state.chain_info.best_block_height
        }
        WalletType::Hot => {
            wallet_info.best_block.1.next_height() < node_state.chain_info.best_block_height
        }
    };

    let scan_progress_widget = if show_scan_progress {
        // TODO: Fix scan progress when the node is in the initial block download state
        let scan_progress = wallet_scan_progress(
            node_state.chain_info.best_block_height.into_int(),
            wallet_info.best_block.1.into_int(),
        );
        let scan_progress_str = format!(
            "{:.0}%\n({}/{} blocks)",
            scan_progress,
            wallet_info.best_block.1.into_int(),
            node_state.chain_info.best_block_height.into_int()
        );
        column![
            text(scan_progress_str)
                .align_x(iced::alignment::Horizontal::Center)
                .width(Length::Fill)
                .height(Length::Shrink),
            progress_bar(0.0..=100.0, scan_progress).width(Length::Fill),
        ]
        .padding(10)
        .spacing(10)
        .align_x(Alignment::End)
        .width(Length::Fill)
        .height(Length::Shrink)
    } else {
        Column::new()
    };

    column![
        column![
            text(file_name).size(25),
            row![
                pick_list,
                button(Text::new("+"))
                    .style(iced::widget::button::success)
                    .on_press(WalletMessage::NewAccount),
                tooltip(
                    Text::new(iced_fonts::Bootstrap::Question.to_string())
                        .font(iced_fonts::BOOTSTRAP_FONT),
                    NEW_ACCOUNT_TOOLTIP_TEXT,
                    tooltip::Position::Bottom
                )
                .gap(10)
                .style(iced::widget::container::bordered_box),
            ]
            .align_y(Alignment::Center)
            .spacing(10)
            .width(Length::Fill)
        ]
        .spacing(10)
        .padding(10),
        match wallet_info.wallet_type {
            #[cfg(feature = "trezor")]
            WalletType::Trezor => {
                column![
                    panel_button(
                        "Transactions",
                        SelectedPanel::Transactions,
                        selected_panel,
                        TRANSACTIONS_TOOLTIP_TEXT
                    ),
                    panel_button(
                        "Addresses",
                        SelectedPanel::Addresses,
                        selected_panel,
                        ADDRESSES_TOOLTIP_TEXT
                    ),
                    panel_button(
                        "Send",
                        SelectedPanel::Send,
                        selected_panel,
                        SEND_TOOLTIP_TEXT
                    ),
                    panel_button(
                        "Delegation",
                        SelectedPanel::Delegation,
                        selected_panel,
                        DELEGATION_TOOLTIP_TEXT
                    ),
                    panel_button(
                        "Console",
                        SelectedPanel::Console,
                        selected_panel,
                        CONSOLE_TOOLTIP_TEXT,
                    )
                ]
            }
            WalletType::Cold => {
                column![
                    panel_button(
                        "Addresses",
                        SelectedPanel::Addresses,
                        selected_panel,
                        ADDRESSES_TOOLTIP_TEXT
                    ),
                    panel_button(
                        "Console",
                        SelectedPanel::Console,
                        selected_panel,
                        CONSOLE_TOOLTIP_TEXT,
                    )
                ]
            }
            WalletType::Hot => column![
                panel_button(
                    "Transactions",
                    SelectedPanel::Transactions,
                    selected_panel,
                    TRANSACTIONS_TOOLTIP_TEXT
                ),
                panel_button(
                    "Addresses",
                    SelectedPanel::Addresses,
                    selected_panel,
                    ADDRESSES_TOOLTIP_TEXT
                ),
                panel_button(
                    "Send",
                    SelectedPanel::Send,
                    selected_panel,
                    SEND_TOOLTIP_TEXT
                ),
                panel_button(
                    "Staking",
                    SelectedPanel::Staking,
                    selected_panel,
                    STAKING_TOOLTIP_TEXT
                ),
                panel_button(
                    "Delegation",
                    SelectedPanel::Delegation,
                    selected_panel,
                    DELEGATION_TOOLTIP_TEXT
                ),
                panel_button(
                    "Console",
                    SelectedPanel::Console,
                    selected_panel,
                    CONSOLE_TOOLTIP_TEXT,
                )
            ],
        },
        Column::new().height(Length::Fill),
        scan_progress_widget,
    ]
    .height(Length::Fill)
    .into()
}
