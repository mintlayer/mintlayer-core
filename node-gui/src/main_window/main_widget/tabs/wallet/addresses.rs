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
    widget::{button, column, container, Text},
    Element,
};
use iced_aw::Grid;

use crate::backend::messages::AccountInfo;

use super::WalletMessage;

pub fn view_addresses(
    account: &AccountInfo,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
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
        iced::widget::button(Text::new("New address"))
            .on_press(still_syncing.unwrap_or(WalletMessage::GetNewAddress),)
    ]
    .into()
}
