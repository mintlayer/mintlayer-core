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

use iced::{
    alignment::{Horizontal, Vertical},
    widget::{Column, Container, Text},
    Element, Font, Length, Sandbox, Settings,
};
use iced_aw::{TabLabel, Tabs};

mod dashboard;
use dashboard::{DashboardMessage, DashboardTab};

mod settings;
use settings::{SettingsMessage, SettingsTab, TabPosition};

const HEADER_SIZE: u16 = 32;
const TAB_PADDING: u16 = 16;

const ICON_FONT: Font = iced::Font::External {
    name: "Icons",
    bytes: include_bytes!("../fonts/icons.ttf"),
};

enum Icon {
    User,
    CogAlt,
}

impl From<Icon> for char {
    fn from(icon: Icon) -> Self {
        match icon {
            Icon::User => '\u{E800}',
            Icon::CogAlt => '\u{E802}',
        }
    }
}

fn main() -> iced::Result {
    MintlayerGUI::run(Settings::default())
}

struct MintlayerGUI {
    active_tab: usize,
    dashboard_tab: DashboardTab,
    settings_tab: SettingsTab,
}

#[derive(Clone, Debug)]
enum Message {
    TabSelected(usize),
    Dashboard(DashboardMessage),
    Settings(SettingsMessage),
}

impl Sandbox for MintlayerGUI {
    type Message = Message;

    fn new() -> Self {
        MintlayerGUI {
            active_tab: 0,
            dashboard_tab: DashboardTab::new(),
            settings_tab: SettingsTab::new(),
        }
    }

    fn title(&self) -> String {
        String::from("Mintlayer Node")
    }

    fn update(&mut self, message: Self::Message) {
        match message {
            Message::TabSelected(selected) => self.active_tab = selected,
            Message::Dashboard(message) => self.dashboard_tab.update(message),
            Message::Settings(message) => self.settings_tab.update(message),
        }
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let position = self.settings_tab.settings().tab_bar_position.unwrap_or_default();
        let theme = self.settings_tab.settings().tab_bar_theme.unwrap_or_default();

        Tabs::new(self.active_tab, Message::TabSelected)
            .push(self.dashboard_tab.tab_label(), self.dashboard_tab.view())
            .push(self.settings_tab.tab_label(), self.settings_tab.view())
            .tab_bar_style(theme)
            .icon_font(ICON_FONT)
            .tab_bar_position(match position {
                TabPosition::Top => iced_aw::TabBarPosition::Top,
                TabPosition::Bottom => iced_aw::TabBarPosition::Bottom,
            })
            .into()
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
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .padding(TAB_PADDING)
            .into()
    }

    fn content(&self) -> Element<'_, Self::Message>;
}
