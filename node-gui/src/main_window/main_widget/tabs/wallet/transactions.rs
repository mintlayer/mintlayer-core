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

use common::chain::ChainConfig;
use iced::{
    widget::{container, row, Column, Text},
    Alignment, Element,
};
use iced_aw::Grid;

use crate::{
    backend::messages::AccountInfo,
    main_window::{print_block_timestamp, print_coin_amount},
};

use super::WalletMessage;

pub fn view_transactions(
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
        let timestamp = tx.block.as_ref().map_or_else(
            || "-".to_owned(),
            |block| print_block_timestamp(block.timestamp),
        );
        transaction_list = transaction_list
            .push(field(format!("{}", current_transaction_list.skip + index)))
            .push(field(tx.txid.to_string()))
            .push(field(timestamp))
            .push(field(tx.tx_type.type_name().to_owned()))
            .push(field(amount_str));
    }

    let page_index = current_transaction_list.skip / current_transaction_list.count;
    let page_count =
        current_transaction_list.total.saturating_sub(1) / current_transaction_list.count;
    let prev_enabled = page_index > 0;
    let next_enabled = page_index < page_count;

    let prev_button = iced::widget::button(Text::new("<<"));
    let next_button = iced::widget::button(Text::new(">>"));

    let prev_button = if prev_enabled {
        prev_button.on_press(WalletMessage::TransactionList {
            skip: current_transaction_list.skip.saturating_sub(current_transaction_list.count),
        })
    } else {
        prev_button
    };
    let next_button = if next_enabled {
        next_button.on_press(WalletMessage::TransactionList {
            skip: current_transaction_list.skip.saturating_add(current_transaction_list.count),
        })
    } else {
        next_button
    };

    let transaction_list_controls =
        row![prev_button, Text::new(format!("{}/{}", page_index, page_count)), next_button,]
            .spacing(10)
            .align_items(Alignment::Center);
    transactions = transactions.push(transaction_list).push(transaction_list_controls);

    transactions.into()
}
