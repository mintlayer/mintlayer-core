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

use crate::{backend_controller::NodeBackendController, Message};

#[derive(Debug, Clone)]
pub enum MainWidgetMessage {
    NoOp,
}

pub fn view<'a>(
    backend_controller: &NodeBackendController,
) -> Element<'a, Message, iced::Renderer> {
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

pub fn main_widget_action(msg: MainWidgetMessage) -> Command<Message> {
    match msg {
        MainWidgetMessage::NoOp => Command::none(),
    }
}
