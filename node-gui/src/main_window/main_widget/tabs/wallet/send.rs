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

use common::primitives::DecimalAmount;
use iced::{
    widget::{column, text_input, Text},
    Element,
};

use super::WalletMessage;

pub fn view_send(
    send_address: &str,
    send_amount: &str,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
    column![
        text_input("Address", send_address)
            .on_input(|value| {
                if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                    WalletMessage::SendAddressEdit(value)
                } else {
                    WalletMessage::NoOp
                }
            })
            .padding(15),
        text_input("Amount", send_amount)
            .on_input(|value| {
                if value.parse::<DecimalAmount>().is_ok() || value.is_empty() {
                    WalletMessage::SendAmountEdit(value)
                } else {
                    WalletMessage::NoOp
                }
            })
            .padding(15),
        iced::widget::button(Text::new("Send"))
            .on_press(still_syncing.unwrap_or(WalletMessage::Send))
    ]
    .spacing(10)
    .into()
}
