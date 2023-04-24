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

use crate::{Icon, Message, Tab};
use iced::{
    widget::{Column, Container, Radio, Text},
    Element,
};
use iced_aw::style::TabBarStyles;
use iced_aw::tab_bar::TabLabel;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TabPosition {
    #[default]
    Top,
    Bottom,
}

impl TabPosition {
    pub const ALL: [TabPosition; 2] = [TabPosition::Top, TabPosition::Bottom];
}

impl From<TabPosition> for String {
    fn from(position: TabPosition) -> Self {
        String::from(match position {
            TabPosition::Top => "Top",
            TabPosition::Bottom => "Bottom",
        })
    }
}

//#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TabSettings {
    pub tab_bar_position: Option<TabPosition>,
    pub tab_bar_theme: Option<TabBarStyles>,
}

impl TabSettings {
    pub fn new() -> Self {
        TabSettings {
            tab_bar_position: Some(TabPosition::Top),
            tab_bar_theme: Some(TabBarStyles::default()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SettingsMessage {
    PositionSelected(TabPosition),
    ThemeSelected(TabBarStyles),
}

pub struct SettingsTab {
    settings: TabSettings,
}

impl SettingsTab {
    pub fn new() -> Self {
        SettingsTab {
            settings: TabSettings::new(),
        }
    }

    pub fn settings(&self) -> &TabSettings {
        &self.settings
    }

    pub fn update(&mut self, message: SettingsMessage) {
        match message {
            SettingsMessage::PositionSelected(position) => {
                self.settings.tab_bar_position = Some(position)
            }
            SettingsMessage::ThemeSelected(theme) => self.settings.tab_bar_theme = Some(theme),
        }
    }
}

impl Tab for SettingsTab {
    type Message = Message;

    fn title(&self) -> String {
        String::from("Settings")
    }

    fn tab_label(&self) -> TabLabel {
        //TabLabel::Text(self.title())
        TabLabel::IconText(Icon::CogAlt.into(), self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let content: Element<'_, SettingsMessage> = Container::new(
            Column::new()
                .push(Text::new("TabBar position:").size(20))
                .push(TabPosition::ALL.iter().cloned().fold(
                    Column::new().padding(10).spacing(10),
                    |column, position| {
                        column.push(
                            Radio::new(
                                position,
                                position,
                                self.settings().tab_bar_position,
                                SettingsMessage::PositionSelected,
                            )
                            .size(16),
                        )
                    },
                ))
                .push(Text::new("TabBar color:").size(20))
                .push(
                    (0..5).fold(Column::new().padding(10).spacing(10), |column, id| {
                        column.push(
                            Radio::new(
                                predefined_style(id),
                                predefined_style(id),
                                self.settings().tab_bar_theme,
                                SettingsMessage::ThemeSelected,
                            )
                            .size(16),
                        )
                    }),
                ),
        )
        .into();

        content.map(Message::Settings)
    }
}

fn predefined_style(index: usize) -> TabBarStyles {
    match index {
        0 => TabBarStyles::Default,
        1 => TabBarStyles::Red,
        2 => TabBarStyles::Blue,
        3 => TabBarStyles::Green,
        4 => TabBarStyles::Purple,
        _ => TabBarStyles::Default,
    }
}
