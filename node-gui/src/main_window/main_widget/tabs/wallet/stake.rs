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

use common::{address::Address, chain::ChainConfig, primitives::DecimalAmount};
use iced::{
    widget::{button, column, container, row, text_input, tooltip, tooltip::Position, Text},
    Alignment, Element,
};
use iced_aw::Grid;

use crate::{
    backend::messages::AccountInfo,
    main_window::{print_coin_amount, print_margin_ratio},
};

use super::WalletMessage;
const MIN_PLEDGE_AMOUNT_TOOLTIP_TEXT: &str = "This is the minimum amount that must be pledged in a pool. \
        A pledge is an amount locked in a pool and cannot be taken out (in addition to the rewards that are earned in the pool). \
        Once a pool is decommissioned, the reward will be transferred in a locked state and will be usable after the maturity period.";

pub const MATURITY_PERIOD_TOOLTIP_TEXT: &str = "Any amount in a staking pool, whether staked or delegated, can be freely transferred \
        after this period of time has passed. For pools, the maturity period must pass after decommissioning the pool to make the pledge \
        (and the rewards for that pool) reusable after being locked. \
        For delegations, any amount taken out of a delegation will be locked for the maturity period. The locking is done automatically \
        at the consensus level.";

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

const CREATE_STAKING_POOL_TOOLTIP_TEXT: &str = "A staking pool locks the pledge provided, and can earn you rewards while staking, \
        by securing the network and creating blocks. You can also get other delegators to delegate coins to you, \
        which will earn you extra rewards for staking their coins. Once a pool is created, it will be assigned a pool id, which can be used \
        by other delegators to delegate to you.";

const START_STAKING_TOOLTIP_TEXT: &str =
    "If you have created pools, this will activate staking. The node must be kept running, in order to assist the network in creating blocks and earn rewards.";

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
            let mut staking_balance_grid = Grid::with_columns(5)
                .push(field("Pool Id".to_owned()))
                .push(field(String::new()))
                .push(field("Margin ratio".to_owned()))
                .push(field("Cost per block".to_owned()))
                .push(field("Pool balance".to_owned()));
            for (pool_id, (pool_data, balance)) in account.staking_balance.iter() {
                let pool_id_address = Address::new(chain_config, pool_id)
                    .expect("Encoding pool id to address can't fail (GUI)");
                staking_balance_grid = staking_balance_grid
                    .push(
                        tooltip(
                            field(pool_id_address.to_short_string()),
                            pool_id_address.to_string(),
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
                        .on_press(WalletMessage::CopyToClipboard(pool_id_address.to_string())),
                    )
                    .push(field(print_margin_ratio(
                        pool_data.margin_ratio_per_thousand,
                    )))
                    .push(field(print_coin_amount(
                        chain_config,
                        pool_data.cost_per_block,
                    )))
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
                .on_press(still_syncing.clone().unwrap_or(WalletMessage::ToggleStaking(new_state))),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                START_STAKING_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ]
    } else {
        row![]
    };

    let min_pledge_text = format!(
        "Minimum pledge to create a pool: {} {}",
        chain_config
            .min_stake_pool_pledge()
            .into_fixedpoint_str(chain_config.coin_decimals()),
        chain_config.coin_ticker()
    );

    let maturity_period = chain_config.staking_pool_spend_maturity_block_count(1.into()).to_int();
    let maturity_period_text = format!(
        "Maturity period: {maturity_period} blocks (a block takes on average {} seconds)",
        chain_config.target_block_spacing().as_secs()
    );

    column![
        row![Text::new(min_pledge_text).size(13),
        tooltip(
            Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
            MIN_PLEDGE_AMOUNT_TOOLTIP_TEXT,
            Position::Bottom)
        .gap(10)
        .style(iced::theme::Container::Box)],
        row![Text::new(maturity_period_text).size(13),
        tooltip(
            Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
            MATURITY_PERIOD_TOOLTIP_TEXT,
            Position::Bottom)
        .gap(10)
        .style(iced::theme::Container::Box)],
        row![
            text_input("Pledge amount for the new staking pool", stake_amount)
                .on_input(|value| {
                    if value.parse::<DecimalAmount>().is_ok() || value.is_empty() {
                        WalletMessage::StakeAmountEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                 })
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
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_digit()) {
                        WalletMessage::CostPerBlockEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
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
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_digit() | (ch=='.') | (ch=='%')) {
                        WalletMessage::MarginPerThousandEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
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
                .on_input(|value| {
                    if value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                        WalletMessage::DecommissionAddressEdit(value)
                    } else {
                        WalletMessage::NoOp
                    }
                })
                .padding(15),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                DECOMMISSION_ADDRESS_TOOLTIP_TEXT,
                Position::Bottom)
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        row![
            iced::widget::button(Text::new("Create staking pool"))
                .padding(15)
                .on_press(still_syncing.unwrap_or(WalletMessage::CreateStakingPool)),
            tooltip(
                Text::new(iced_aw::Icon::Question.to_string()).font(iced_aw::ICON_FONT),
                CREATE_STAKING_POOL_TOOLTIP_TEXT,
                Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],

        staking_enabled_row.spacing(10).align_items(Alignment::Center),
        iced::widget::horizontal_rule(10),
        staking_balance_grid,
    ]
    .spacing(10)
    .into()
}
