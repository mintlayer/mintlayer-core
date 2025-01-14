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
    widget::{button, column, container, row, tooltip, Text},
    Element,
};
use iced_aw::{Grid, GridRow};

use node_gui_backend::messages::AccountInfo;

use super::WalletMessage;

const NEW_ADDRESS_TOOLTIP_TEXT: &str = "You can create as many addresses as you desire; however, you're limited by how many addresses you create before using them. An address is labeled as used, when a transaction is found on the blockchain that utilizes that address.";

pub fn view_addresses(
    account: &AccountInfo,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);
    let addresses = account
        .addresses
        .iter()
        .map(|(index, address)| {
            GridRow::new().push(field(index.to_string())).push(field(address.clone())).push(
                button(
                    Text::new(iced_fonts::Bootstrap::ClipboardCheck.to_string())
                        .font(iced_fonts::BOOTSTRAP_FONT),
                )
                .style(iced::widget::button::text)
                .on_press(WalletMessage::CopyToClipboard(address.as_str().to_owned())),
            )
        })
        .fold(Grid::new(), |grid, row| grid.push(row));

    column![
        addresses,
        row![
            iced::widget::button(Text::new("New address"))
                .on_press(still_syncing.unwrap_or(WalletMessage::GetNewAddress)),
            tooltip(
                Text::new(iced_fonts::Bootstrap::Question.to_string())
                    .font(iced_fonts::BOOTSTRAP_FONT),
                NEW_ADDRESS_TOOLTIP_TEXT,
                tooltip::Position::Bottom
            )
            .gap(10)
        ],
    ]
    .into()
}
