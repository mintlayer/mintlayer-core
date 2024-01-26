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

use std::collections::BTreeMap;

use common::{
    address::Address,
    chain::{ChainConfig, DelegationId},
    primitives::DecimalAmount,
};
use iced::{
    widget::{button, column, container, row, text_input, tooltip, tooltip::Position, Text},
    Element, Length,
};
use iced_aw::Grid;

use crate::{backend::messages::AccountInfo, main_window::print_coin_amount};

use super::WalletMessage;

const POOL_ID_TOOLTIP_TEXT: &str =
    "The pool id of the pool that will get the delegation and stake the coins.";
const DELEGATION_ADDRESS_TOOLTIP_TEXT: &str =
    "The address, that will have the authority to sign withdrawals from a pool.";

const SEND_DELEGATION_ADDRESS_TOOLTIP_TEXT: &str = " The address that will be receiving the coins";
const SEND_DELEGATION_AMOUNT_TOOLTIP_TEXT: &str =
    "The amount that will be taken away from the delegation";
const SEND_DELEGATION_ID_TOOLTIP_TEXT: &str =
    "The delegation id, from which the delegated coins will be taken";

#[allow(clippy::too_many_arguments)]
pub fn view_delegation(
    chain_config: &ChainConfig,
    account: &AccountInfo,
    pool_id: &str,
    delegation_address: &str,
    send_delegation_address: &str,
    send_delegation_amount: &str,
    send_delegation_id: &str,
    delegate_staking_amounts: &BTreeMap<DelegationId, String>,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);

    let delegation_balance_grid = {
        // We print the table only if there are delegations
        if account.delegations_balance.is_empty() {
            Grid::with_columns(2)
                .push(field("No delegations found".to_owned()))
                .push(field(String::new()))
        } else {
            let mut delegation_balance_grid = Grid::with_columns(7)
                .push(field("Delegation Id".to_owned()))
                .push(field("".to_owned()))
                .push(field("Pool Id".to_owned()))
                .push(field("".to_owned()))
                .push(field("Delegation balance".to_owned()))
                .push(field("".to_owned()))
                .push(field("".to_owned()));
            for (delegation_id, pool_id, balance) in account
                .delegations_balance
                .iter()
                .map(|(del_id, (pool_id, b))| (*del_id, *pool_id, *b))
            {
                let delegation_address = Address::new(chain_config, &delegation_id)
                    .expect("Encoding pool id to address can't fail (GUI)");
                let pool_address = Address::new(chain_config, &pool_id)
                    .expect("Encoding pool id to address can't fail (GUI)");
                let delegate_staking_amount =
                    delegate_staking_amounts.get(&delegation_id).cloned().unwrap_or(String::new());
                delegation_balance_grid = delegation_balance_grid
                    .push(
                        tooltip(
                            field(
                                delegation_address
                                    .to_short_string(chain_config)
                                    .expect("cannot fail"),
                            ),
                            delegation_address.to_string(),
                            Position::Bottom,
                        )
                        .gap(5)
                        .style(iced::theme::Container::Box),
                    )
                    .push(
                        button(
                            Text::new(iced_aw::Icon::ClipboardCheck.to_string())
                                .font(iced_aw::ICON_FONT),
                        )
                        .style(iced::theme::Button::Text)
                        .width(Length::Shrink)
                        .on_press(WalletMessage::CopyToClipboard(
                            delegation_address.to_string(),
                        )),
                    )
                    .push(
                        tooltip(
                            field(pool_address.to_short_string(chain_config).expect("cannot fail")),
                            pool_address.to_string(),
                            Position::Bottom,
                        )
                        .gap(5)
                        .style(iced::theme::Container::Box),
                    )
                    .push(
                        button(
                            Text::new(iced_aw::Icon::ClipboardCheck.to_string())
                                .font(iced_aw::ICON_FONT),
                        )
                        .style(iced::theme::Button::Text)
                        .width(Length::Shrink)
                        .on_press(WalletMessage::CopyToClipboard(pool_address.to_string())),
                    )
                    .push(field(print_coin_amount(chain_config, balance)))
                    .push(
                        text_input("Amount", &delegate_staking_amount)
                            .on_input(move |value| {
                                if value.parse::<DecimalAmount>().is_ok() || value.is_empty() {
                                    WalletMessage::DelegationAmountEdit((delegation_id, value))
                                } else {
                                    WalletMessage::NoOp
                                }
                            })
                            .padding(5)
                            .width(Length::Fixed(100.)),
                    )
                    .push(
                        button(Text::new("Delegate")).on_press(
                            still_syncing
                                .clone()
                                .unwrap_or(WalletMessage::DelegateStaking(delegation_id)),
                        ),
                    );
            }
            delegation_balance_grid
        }
    };

    column![
        // ----- Create delegation
        row![
            text_input("Pool Id for new delegation", pool_id)
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                        WalletMessage::DelegationPoolIdEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(10),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                POOL_ID_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
        row![
            text_input("Delegation address", delegation_address)
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                        WalletMessage::DelegationAddressEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(10),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                DELEGATION_ADDRESS_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
        iced::widget::button(Text::new("Create delegation"))
            .padding(10)
            .on_press(still_syncing.clone().unwrap_or(WalletMessage::CreateDelegation)),
        iced::widget::horizontal_rule(10),
        // ----- Send delegation to address
        row![
            text_input("Address", send_delegation_address)
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                        WalletMessage::SendDelegationAddressEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(10),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                SEND_DELEGATION_ADDRESS_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
        row![
            text_input("Amount to send", send_delegation_amount)
                .on_input(|value| {
                    if value.parse::<DecimalAmount>().is_ok() || value.is_empty() {
                        WalletMessage::SendDelegationAmountEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(10),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                SEND_DELEGATION_AMOUNT_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
        row![
            text_input("Delegation Id", send_delegation_id)
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                        WalletMessage::SendDelegationIdEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(10),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                SEND_DELEGATION_ID_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
        iced::widget::button(Text::new("Send to address from delegation"))
            .padding(10)
            .on_press(still_syncing.unwrap_or(WalletMessage::SendDelegationToAddress)),
        iced::widget::horizontal_rule(10),
        // ----- Delegation balance grid
        delegation_balance_grid,
    ]
    .spacing(10)
    .into()
}
