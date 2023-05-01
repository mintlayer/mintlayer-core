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

use iced::{
    alignment,
    widget::{container, text},
    Command, Element, Length,
};
use iced_aw::tab_bar::TabLabel;

use crate::backend_controller::NodeBackendController;

use super::{Icon, Tab, TabsMessage};

#[derive(Debug, Clone)]
pub enum SummaryMessage {
    NoOp,
}

pub struct SummaryTab {
    controller: NodeBackendController,
}

impl SummaryTab {
    pub fn new(controller: NodeBackendController) -> Self {
        SummaryTab { controller }
    }

    pub fn update(&mut self, message: SummaryMessage) -> Command<SummaryMessage> {
        match message {
            SummaryMessage::NoOp => Command::none(),
        }
    }
}

impl Tab for SummaryTab {
    type Message = TabsMessage;

    fn title(&self) -> String {
        String::from("Summary")
    }

    fn tab_label(&self) -> TabLabel {
        // TabLabel::Text(self.title())
        TabLabel::IconText(Icon::User.into(), self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        genesis_block_label_field(&self.controller)
    }
}

pub fn genesis_block_label_field<'a>(
    backend_controller: &NodeBackendController,
) -> Element<'a, TabsMessage, iced::Renderer> {
    let main_widget = text(&format!(
        "Genesis block: {}",
        backend_controller.chain_config().genesis_block_id(),
    ))
    .width(Length::Fill)
    .size(25)
    .horizontal_alignment(alignment::Horizontal::Center)
    .vertical_alignment(alignment::Vertical::Center);

    let c = container(main_widget);

    c.into()
}
