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

use iced::Element;

use crate::{backend_controller::NodeBackendController, Message};

pub mod main_menu;
pub mod main_widget;

pub struct MainWindow {
    pub main_menu: main_menu::MainMenu,
    pub main_widget: main_widget::MainWidget,
}

impl MainWindow {
    pub fn new(backend_controller: NodeBackendController) -> Self {
        Self {
            main_menu: main_menu::MainMenu::new(backend_controller.clone()),
            main_widget: main_widget::MainWidget::new(backend_controller),
        }
    }

    pub fn view(
        &self,
        backend_controller: &NodeBackendController,
    ) -> Element<'_, Message, iced::Renderer> {
        let c = iced::widget::column![
            iced::widget::row!(self.main_menu.view(backend_controller).map(Message::MenuMessage)),
            iced::widget::row!(self
                .main_widget
                .view(backend_controller)
                .map(Message::MainWidgetMessage))
        ];

        c.into()
    }
}
