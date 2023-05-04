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

mod tabs;

use iced::{Command, Element};

use crate::backend_controller::NodeBackendController;

#[derive(Debug, Clone)]
pub enum MainWidgetMessage {
    Start,
    TabsMessage(tabs::TabsMessage),
}

pub struct MainWidget {
    tabs: tabs::TabsWidget,
}

impl MainWidget {
    pub fn new(backend_controller: NodeBackendController) -> Self {
        Self {
            tabs: tabs::TabsWidget::new(backend_controller),
        }
    }

    pub fn start() -> Vec<Command<MainWidgetMessage>> {
        vec![iced::Command::perform(async {}, |_| {
            MainWidgetMessage::TabsMessage(tabs::TabsMessage::Start)
        })]
    }

    pub fn update(&mut self, msg: MainWidgetMessage) -> Command<MainWidgetMessage> {
        match msg {
            MainWidgetMessage::Start => iced::Command::batch(Self::start()),
            MainWidgetMessage::TabsMessage(tabs_message) => {
                self.tabs.update(tabs_message).map(MainWidgetMessage::TabsMessage)
            }
        }
    }

    pub fn view(
        &self,
        backend_controller: &NodeBackendController,
    ) -> Element<'_, MainWidgetMessage, iced::Renderer> {
        self.tabs.view(backend_controller).map(MainWidgetMessage::TabsMessage)
    }
}
