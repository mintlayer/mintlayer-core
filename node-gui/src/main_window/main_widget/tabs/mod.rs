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
    widget::{Column, Container, Text},
    Command, Element, Length,
};
use iced_aw::{TabLabel, Tabs};

use crate::backend_controller::NodeBackendController;

use self::{
    settings::{SettingsMessage, SettingsTab, TabBarPosition},
    summary::{SummaryMessage, SummaryTab},
};

pub mod settings;
pub mod summary;

const HEADER_SIZE: u16 = 32;
const TAB_PADDING: u16 = 16;

// enum Icon {
//     User,
//     CogAlt,
// }

// impl From<Icon> for char {
//     fn from(icon: Icon) -> Self {
//         match icon {
//             Icon::User => '\u{E800}',
//             Icon::CogAlt => '\u{E802}',
//         }
//     }
// }

#[derive(Debug, Clone)]
pub enum TabsMessage {
    TabSelected(usize),
    Counter(SummaryMessage),
    Settings(SettingsMessage),
}

pub struct TabsWidget {
    active_tab: usize,
    counter_tab: SummaryTab,
    settings_tab: SettingsTab,
}

impl TabsWidget {
    pub fn new(backend_controller: NodeBackendController) -> Self {
        TabsWidget {
            active_tab: 0,
            counter_tab: SummaryTab::new(backend_controller),
            settings_tab: SettingsTab::new(),
        }
    }

    pub fn view(
        &self,
        _backend_controller: &NodeBackendController,
    ) -> Element<'_, TabsMessage, iced::Renderer> {
        let position = self.settings_tab.settings().tab_bar_position.unwrap_or_default();
        let theme = self.settings_tab.settings().tab_bar_theme.unwrap_or_default();

        Tabs::new(self.active_tab, TabsMessage::TabSelected)
            .push(self.counter_tab.tab_label(), self.counter_tab.view())
            .push(self.settings_tab.tab_label(), self.settings_tab.view())
            .tab_bar_style(theme)
            // .icon_font(ICON_FONT)
            .tab_bar_position(match position {
                TabBarPosition::Top => iced_aw::TabBarPosition::Top,
                TabBarPosition::Bottom => iced_aw::TabBarPosition::Bottom,
            })
            .into()
    }

    pub fn update(&mut self, msg: TabsMessage) -> iced::Command<TabsMessage> {
        match msg {
            TabsMessage::TabSelected(n) => {
                self.active_tab = n;
                Command::none()
            }
            TabsMessage::Counter(message) => {
                self.counter_tab.update(message).map(TabsMessage::Counter)
            }
            TabsMessage::Settings(message) => {
                self.settings_tab.update(message).map(TabsMessage::Settings)
            }
        }
    }
}

trait Tab {
    type Message;

    fn title(&self) -> String;

    fn tab_label(&self) -> TabLabel;

    fn view(&self) -> Element<'_, Self::Message> {
        let column = Column::new()
            .spacing(20)
            .push(Text::new(self.title()).size(HEADER_SIZE))
            .push(self.content());

        Container::new(column)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(alignment::Horizontal::Center)
            .align_y(alignment::Vertical::Center)
            .padding(TAB_PADDING)
            .into()
    }

    fn content(&self) -> Element<'_, Self::Message>;
}
