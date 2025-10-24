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
    widget::{column, container, Text},
    Element, Length, Task,
};
use iced_aw::{tab_bar::TabLabel, Grid, GridRow};

use crate::main_window::NodeState;

use super::{Tab, TabsMessage};

#[derive(Debug, Clone)]
pub enum NetworkingMessage {}

pub struct NetworkingTab {}

impl NetworkingTab {
    pub fn new() -> Self {
        NetworkingTab {}
    }

    pub fn update(&mut self, message: NetworkingMessage) -> Task<NetworkingMessage> {
        match message {}
    }
}

impl Tab for NetworkingTab {
    type Message = TabsMessage;

    fn tab_label(&self, _node_state: &NodeState) -> TabLabel {
        TabLabel::IconText(
            iced_fonts::Bootstrap::Wifi.into(),
            String::from("Networking"),
        )
    }

    fn content(&self, node_state: &NodeState) -> Element<'_, Self::Message> {
        let header = |text: &'static str| container(Text::new(text)).padding(5);
        let field = |text: String| container(Text::new(text)).padding(5);
        let peers = Grid::new().push(
            GridRow::new()
                .push(header("#"))
                .push(header("Socket"))
                .push(header("Inbound"))
                .push(header("User agent"))
                .push(header("Version")),
        );
        let peers = node_state
            .connected_peers
            .iter()
            .map(|(peer_id, peer)| {
                let inbound_str = if peer.inbound { "Inbound" } else { "Outbound" };
                GridRow::new()
                    .push(field(peer_id.to_string()))
                    .push(field(peer.address.clone()))
                    .push(field(inbound_str.to_string()))
                    .push(field(peer.user_agent.to_string()))
                    .push(field(peer.version.to_string()))
            })
            .fold(peers, |grid, row| grid.push(row));

        column![
            Text::new("The following is a list of peers connected to your node").size(16),
            peers
        ]
        .padding(10)
        .spacing(15)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
    }
}
