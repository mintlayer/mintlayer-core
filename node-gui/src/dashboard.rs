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

use common::{
    chain::GenBlock,
    primitives::{BlockHeight, Id, H256},
};
use iced::{
    alignment::{Horizontal, Vertical},
    widget::{Column, Container, Text},
    Alignment, Element,
};
use iced_aw::tab_bar::TabLabel;

use crate::{Icon, Message, Tab};

#[derive(Debug, Clone)]
pub enum DashboardMessage {
    // Messages are sent from GUI controls to update() to update the inner value
}

pub struct DashboardTab {
    current_tip: (Id<GenBlock>, BlockHeight),
}

impl DashboardTab {
    pub fn new() -> Self {
        DashboardTab {
            current_tip: (Id::new(H256::zero()), 0.into()),
        }
    }

    pub fn update(&mut self, message: DashboardMessage) {
        match message {}
    }
}

impl Tab for DashboardTab {
    type Message = Message;

    fn title(&self) -> String {
        String::from("Dashboard")
    }

    fn tab_label(&self) -> TabLabel {
        //TabLabel::Text(self.title())
        TabLabel::IconText(Icon::User.into(), self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let content: Element<'_, DashboardMessage> = Container::new(
            Column::new()
                .align_items(Alignment::Center)
                .max_width(600)
                .padding(20)
                .spacing(16)
                .push(Text::new(self.current_tip.0.to_string()).size(32))
                .push(Text::new(self.current_tip.1.to_string()).size(32)),
        )
        .align_x(Horizontal::Center)
        .align_y(Vertical::Center)
        .into();

        content.map(Message::Dashboard)
    }
}
