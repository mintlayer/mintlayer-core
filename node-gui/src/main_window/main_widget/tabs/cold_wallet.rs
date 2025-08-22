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

use common::chain::ChainConfig;
use iced::{
    widget::{column, Text},
    Element, Length,
};
use iced_aw::tab_bar::TabLabel;

use crate::main_window::NodeState;

use super::{Tab, TabsMessage};

pub struct ColdWalletTab {}

impl ColdWalletTab {
    pub fn new() -> Self {
        ColdWalletTab {}
    }
}

fn get_network_type_capitalized(chain_config: &ChainConfig) -> String {
    let mut network_type = chain_config.chain_type().name().to_string();
    format!("{}{network_type}", network_type.remove(0).to_uppercase())
}

impl Tab for ColdWalletTab {
    type Message = TabsMessage;

    fn tab_label(&self, _node_state: &NodeState) -> TabLabel {
        TabLabel::IconText(
            iced_fonts::Bootstrap::Info.into(),
            String::from("Cold wallet summary"),
        )
    }

    fn content(&self, node_state: &NodeState) -> Element<'_, Self::Message> {
        let network_type = get_network_type_capitalized(node_state.chain_config());

        let msg = format!("Running in cold wallet mode on {network_type}\nOpen a wallet from the file menu to start");
        column![Text::new(msg).size(16)]
            .padding(10)
            .spacing(15)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
}
