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
    widget::{button, column, pick_list, progress_bar, row, text, Column, Text},
    Alignment, Element, Length,
};

use crate::{
    backend::messages::{AccountId, WalletInfo},
    main_window::NodeState,
};

use super::{SelectedPanel, WalletMessage};

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
    let show_scan_progress =
        wallet_info.best_block.1.next_height() < node_state.chain_info.best_block_height;
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
                .horizontal_alignment(iced::alignment::Horizontal::Center)
                .width(Length::Fill)
                .height(Length::Shrink),
            progress_bar(0.0..=100.0, scan_progress).width(Length::Fill),
        ]
        .padding(10)
        .spacing(10)
        .align_items(Alignment::End)
        .width(Length::Fill)
        .height(Length::Shrink)
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
            panel_button("Staking", SelectedPanel::Staking, selected_panel),
        ],
        Column::new().height(Length::Fill),
        scan_progress_widget,
    ]
    .height(Length::Fill)
    .into()
}
