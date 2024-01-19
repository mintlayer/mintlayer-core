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

use common::{address::Address, chain::ChainConfig};
use iced::{
    widget::{column, container, row, text_input, tooltip, tooltip::Position, Text},
    Alignment, Element,
};
use iced_aw::Grid;

use crate::{backend::messages::AccountInfo, main_window::print_coin_amount};

use super::WalletMessage;

const PLEDGE_AMOUNT_TOOLTIP_TEXT: &str ="The amount to be pledged to the pool. There is a minimum to be accepted. \
        This amount, and the rewards gained by the pool, CANNOT be taken out without decommissioning the pool. \
        If you'd like to withdraw rewards, consider creating a pool and delegating to yourself. \
        Delegators have no restrictions on withdrawals. \
        The likelihood to win block rewards, by creating blocks while staking, is proportional to how much the pool owns, \
        up to a maximum, to discourage heavy centralization of power.";

const COST_PER_BLOCK_TOOLTIP_TEXT: &str = "An amount in coins to be subtracted from the total rewards in a block and handed to the staker \
        as a constant/fixed cost for running the pool.";

const MARGIN_PER_THOUSAND_TOOLTIP_TEXT: &str = "After subtracting \"cost per block\" from the reward, this ratio is taken from the rewards and is handed to the staker. \
        What is left is distributed among delegators, pro-rata, based on their delegation amounts. \
        The amount here is written as a percentage with per-mill accuracy. For example, 0.1% is valid, \
        and is equivalent to 0.001. Also 5% is valid and is equivalent to 0.05.";

const DECOMMISSION_ADDRESS_TOOLTIP_TEXT: &str = "The key that can decommission the pool. It's recommended to keep the decommission key in a cold storage.";

pub fn view_stake(
    chain_config: &ChainConfig,
    account: &AccountInfo,
    stake_amount: &str,
    mpt: &str,
    cost_per_block: &str,
    decommission_key: &str,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
    let field = |text: String| container(Text::new(text)).padding(5);

    let staking_balance_grid = {
        // We print the table only if there are staking pools
        if account.staking_balance.is_empty() {
            Grid::with_columns(2)
                .push(field("No staking pools found".to_owned()))
                .push(field(String::new()))
        } else {
            let mut staking_balance_grid = Grid::with_columns(2)
                .push(field("Pool Id".to_owned()))
                .push(field("Pool balance".to_owned()));
            for (pool_id, balance) in account.staking_balance.iter() {
                staking_balance_grid = staking_balance_grid
                    .push(field(
                        Address::new(chain_config, pool_id)
                            .expect("Encoding pool id to address can't fail (GUI)")
                            .to_string(),
                    ))
                    .push(field(print_coin_amount(chain_config, *balance)));
            }
            staking_balance_grid
        }
    };

    // We only show the staking button if there's something to stake
    let staking_enabled_row = if !account.staking_balance.is_empty() {
        let (staking_status, staking_button, new_state) = if account.staking_enabled {
            ("Staking running", "Stop", false)
        } else {
            ("Staking is stopped", "Start", true)
        };

        row![
            Text::new(staking_status),
            iced::widget::button(Text::new(staking_button))
                .on_press(still_syncing.clone().unwrap_or(WalletMessage::ToggleStaking(new_state)))
        ]
    } else {
        row![]
    };

    column![
        row![
            text_input("Pledge amount for the new staking pool", stake_amount)
                .on_input(|value| { WalletMessage::StakeAmountEdit(value) })
                .padding(15),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                PLEDGE_AMOUNT_TOOLTIP_TEXT,
                Position::Bottom)
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        row![
            text_input("Cost per block", cost_per_block)
                .on_input(|value| { WalletMessage::CostPerBlockEdit(value) })
                .padding(15),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                COST_PER_BLOCK_TOOLTIP_TEXT,
                Position::Bottom)
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        row![
            text_input("Margin ratio per thousand. The decimal must be in the range [0.001,1.000] or [0.1%,100%]", mpt)
                .on_input(|value| { WalletMessage::MarginPerThousandEdit(value) })
                .padding(15),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                MARGIN_PER_THOUSAND_TOOLTIP_TEXT,
                Position::Bottom)
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        row![
            text_input("Decommission address", decommission_key)
                .on_input(|value| { WalletMessage::DecommissionAddressEdit(value) })
                .padding(15),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                DECOMMISSION_ADDRESS_TOOLTIP_TEXT,
                Position::Bottom)
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        iced::widget::button(Text::new("Create staking pool"))
            .padding(15)
            .on_press(still_syncing.unwrap_or(WalletMessage::CreateStakingPool)),
        staking_enabled_row.spacing(10).align_items(Alignment::Center),
        iced::widget::horizontal_rule(10),
        staking_balance_grid,
    ]
    .spacing(10)
    .into()
}
