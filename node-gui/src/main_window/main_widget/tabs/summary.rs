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

use iced::{
    widget::{column, Text},
    Command, Element, Length,
};
use iced_aw::{tab_bar::TabLabel, Grid};

use crate::main_window::{print_block_timestamp, NodeState};

use super::{Tab, TabsMessage};

use serialization::hex::HexEncode;

#[derive(Debug, Clone)]
pub enum SummaryMessage {}

pub struct SummaryTab {}

impl SummaryTab {
    pub fn new() -> Self {
        SummaryTab {}
    }

    pub fn update(&mut self, message: SummaryMessage) -> Command<SummaryMessage> {
        match message {}
    }
}

impl Tab for SummaryTab {
    type Message = TabsMessage;

    fn title(&self) -> String {
        String::from("Summary")
    }

    fn tab_label(&self) -> TabLabel {
        TabLabel::IconText(iced_aw::Icon::Info.into(), self.title())
    }

    fn content(&self, node_state: &NodeState) -> Element<Self::Message> {
        let chainstate = Grid::with_columns(2)
            .push(Text::new("Best block id "))
            .push(Text::new(node_state.chain_info.best_block_id.hex_encode()))
            .push(Text::new("Best block height "))
            .push(Text::new(
                node_state.chain_info.best_block_height.to_string(),
            ))
            .push(Text::new("Best block timestamp (UTC) "))
            .push(Text::new(print_block_timestamp(
                node_state.chain_info.best_block_timestamp,
            )));

        column![chainstate]
            .padding(10)
            .spacing(15)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
}
