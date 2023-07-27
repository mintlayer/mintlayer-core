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
    widget::{column, container, row, text_input, Text},
    Alignment, Element,
};
use iced_aw::Grid;
use serialization::hex::HexEncode;

use crate::{backend::messages::AccountInfo, main_window::print_coin_amount};

use super::WalletMessage;

pub fn view_stake(
    chain_config: &ChainConfig,
    account: &AccountInfo,
    stake_amount: &str,
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
                    .push(field(pool_id.hex_encode()))
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
                .on_press(WalletMessage::ToggleStaking(new_state))
        ]
    } else {
        row![]
    };

    column![
        row![
            text_input("Pledge amount for the new staking pool", stake_amount)
                .on_input(|value| { WalletMessage::StakeAmountEdit(value) })
                .padding(15),
            iced::widget::button(Text::new("Create staking pool"))
                .padding(15)
                .on_press(WalletMessage::CreateStakingPool)
        ],
        staking_enabled_row.spacing(10).align_items(Alignment::Center),
        iced::widget::horizontal_rule(10),
        staking_balance_grid,
    ]
    .spacing(10)
    .into()
}
