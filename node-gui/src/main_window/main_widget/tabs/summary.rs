// Copyright (c) 2021-2023 RBB S.r.l
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

use std::fmt::Debug;

use common::chain::ChainConfig;
use iced::{
    widget::{column, tooltip, Text},
    Element, Length, Task,
};
use iced_aw::{tab_bar::TabLabel, Grid, GridRow};

use crate::main_window::{print_block_timestamp, NodeState};

use super::{Tab, TabsMessage};

use serialization::hex::HexEncode;

const NETWORK_TOOLTIP: &str = "Mintlayer supports multiple types of networks for different purposes. The 'Mainnet' is the main network that has coins with value. The 'Testnet' is the network with coins that have no value, but is used for testing various applications before deploying them on Mainnet.";

#[derive(Debug, Clone)]
pub enum SummaryMessage {}

pub struct SummaryTab {}

impl SummaryTab {
    pub fn new() -> Self {
        SummaryTab {}
    }

    pub fn update(&mut self, message: SummaryMessage) -> Task<SummaryMessage> {
        match message {}
    }
}

fn get_network_type_capitalized(chain_config: &ChainConfig) -> String {
    let mut network_type = chain_config.chain_type().name().to_string();
    format!("{}{network_type}", network_type.remove(0).to_uppercase())
}

impl Tab for SummaryTab {
    type Message = TabsMessage;

    fn tab_label(&self, _node_state: &NodeState) -> TabLabel {
        TabLabel::IconText(iced_fonts::Bootstrap::Info.into(), String::from("Summary"))
    }

    fn content(&self, node_state: &NodeState) -> Element<Self::Message> {
        let network_type = get_network_type_capitalized(node_state.chain_config());
        let chainstate = Grid::new()
            .push(
                GridRow::new().push(Text::new("Network ")).push(
                    tooltip(
                        Text::new(network_type),
                        NETWORK_TOOLTIP,
                        tooltip::Position::Bottom,
                    )
                    .gap(10)
                    .style(iced::widget::container::bordered_box),
                ),
            )
            .push(
                GridRow::new()
                    .push(Text::new("Best block id "))
                    .push(Text::new(node_state.chain_info.best_block_id.hex_encode())),
            )
            .push(
                GridRow::new().push(Text::new("Best block height ")).push(Text::new(
                    node_state.chain_info.best_block_height.to_string(),
                )),
            )
            .push(
                GridRow::new().push(Text::new("Best block timestamp (UTC) ")).push(Text::new(
                    print_block_timestamp(node_state.chain_info.best_block_timestamp),
                )),
            );

        column![
            Text::new("The following is the syncing state of your node. In a healthy network, the block timestamp should be close to the current wall-clock time.").size(16),
            chainstate
        ]
        .padding(10)
        .spacing(15)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
    }
}
