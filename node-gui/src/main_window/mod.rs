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

use iced::{Command, Element};

use crate::{
    backend_controller::NodeBackendController,
    main_window::{main_menu::MenuMessage, main_widget::MainWidgetMessage},
};

mod main_menu;
mod main_widget;

pub struct MainWindow {
    pub main_menu: main_menu::MainMenu,
    pub main_widget: main_widget::MainWidget,
}

#[derive(Debug, Clone)]
pub enum MainWindowMessage {
    Start,
    MenuMessage(main_menu::MenuMessage),
    MainWidgetMessage(main_widget::MainWidgetMessage),
}

impl MainWindow {
    pub fn new(backend_controller: NodeBackendController) -> Self {
        Self {
            main_menu: main_menu::MainMenu::new(backend_controller.clone()),
            main_widget: main_widget::MainWidget::new(backend_controller),
        }
    }

    pub fn start() -> Vec<Command<MainWindowMessage>> {
        vec![
            iced::Command::perform(async {}, |_| {
                MainWindowMessage::MainWidgetMessage(MainWidgetMessage::Start)
            }),
            iced::Command::perform(async {}, |_| {
                MainWindowMessage::MenuMessage(MenuMessage::Start)
            }),
        ]
    }

    pub fn update(&mut self, msg: MainWindowMessage) -> iced::Command<MainWindowMessage> {
        match msg {
            MainWindowMessage::Start => iced::Command::batch(Self::start()),
            MainWindowMessage::MenuMessage(menu_message) => {
                self.main_menu.update(menu_message).map(MainWindowMessage::MenuMessage)
            }
            MainWindowMessage::MainWidgetMessage(main_widget_message) => self
                .main_widget
                .update(main_widget_message)
                .map(MainWindowMessage::MainWidgetMessage),
        }
    }

    pub fn view(
        &self,
        backend_controller: &NodeBackendController,
    ) -> Element<'_, MainWindowMessage, iced::Renderer> {
        let c = iced::widget::column![
            iced::widget::row!(self
                .main_menu
                .view(backend_controller)
                .map(MainWindowMessage::MenuMessage)),
            iced::widget::row!(self
                .main_widget
                .view(backend_controller)
                .map(MainWindowMessage::MainWidgetMessage))
        ];

        c.into()
    }
}
