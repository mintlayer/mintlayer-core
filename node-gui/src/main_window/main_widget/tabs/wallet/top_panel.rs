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
    widget::{button, horizontal_space, row, text::LineHeight, tooltip, Text},
    Alignment, Element, Length,
};

use crate::{
    backend::messages::{AccountInfo, EncryptionState, WalletInfo},
    main_window::print_coin_amount_with_ticker,
};

use super::WalletMessage;

const ENCRYPT_WALLET_TOOLTIP_TEXT: &str = "Encrypting the wallet will protect all the private keys and secret information in the wallet. \
    Not everything will be encrypted, but unlocking the wallet will be required to send coins, or do anything that requires private keys. \
    Encryption provides security in case your wallet file was found by someone unauthorized. Keep in mind that if you lose your password, you will absolutely \
    lose access to your wallet and the only way to recover your assets is by using the recovery phrase.";

pub fn view_top_panel(
    chain_config: &ChainConfig,
    wallet_info: &WalletInfo,
    account: &AccountInfo,
) -> Element<'static, WalletMessage> {
    let balance = account.balance.coins();
    let balance = print_coin_amount_with_ticker(chain_config, balance.amount());
    let balance = Text::new(balance).size(20);

    let password = match wallet_info.encryption {
        EncryptionState::EnabledLocked => {
            row![iced::widget::button(Text::new("Unlock").line_height(LineHeight::Relative(1.0)))
                .on_press(WalletMessage::Unlock)]
        }
        EncryptionState::EnabledUnlocked => row![
            iced::widget::button(Text::new("Lock").line_height(LineHeight::Relative(1.0)))
                .on_press(WalletMessage::Lock),
            iced::widget::button(
                Text::new("Disable wallet encryption").line_height(LineHeight::Relative(1.0))
            )
            .on_press(WalletMessage::RemovePassword)
        ],
        EncryptionState::Disabled => row![
            iced::widget::button(
                Text::new("Encrypt wallet").line_height(LineHeight::Relative(1.0))
            )
            .on_press(WalletMessage::SetPassword),
            tooltip(
                Text::new(iced_aw::Bootstrap::Question.to_string())
                    .line_height(LineHeight::Relative(1.0))
                    .font(iced_aw::BOOTSTRAP_FONT),
                ENCRYPT_WALLET_TOOLTIP_TEXT,
                tooltip::Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
    }
    .align_items(Alignment::Center)
    .spacing(10);

    row![
        balance,
        horizontal_space(),
        password,
        button(Text::new("Close wallet").line_height(LineHeight::Relative(1.0)))
            .style(iced::theme::Button::Destructive)
            .on_press(WalletMessage::Close),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(10)
    .padding(10)
    .align_items(Alignment::Center)
    .into()
}
