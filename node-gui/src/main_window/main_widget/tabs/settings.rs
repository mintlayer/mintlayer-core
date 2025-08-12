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
    widget::{column, Column, Container, Radio, Text},
    Element, Length, Task,
};
use iced_aw::tab_bar::TabLabel;

use crate::main_window::NodeState;

use super::{Tab, TabsMessage};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TabBarPosition {
    #[default]
    Top,
    Bottom,
}

impl TabBarPosition {
    pub const ALL: [TabBarPosition; 2] = [TabBarPosition::Top, TabBarPosition::Bottom];
}

impl From<TabBarPosition> for String {
    fn from(position: TabBarPosition) -> Self {
        String::from(match position {
            TabBarPosition::Top => "Top",
            TabBarPosition::Bottom => "Bottom",
        })
    }
}

pub struct TabSettings {
    pub tab_bar_position: Option<TabBarPosition>,
}

impl TabSettings {
    pub fn new() -> Self {
        TabSettings {
            tab_bar_position: Some(TabBarPosition::Top),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SettingsMessage {
    PositionSelected(TabBarPosition),
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

    pub fn update(&mut self, message: SettingsMessage) -> Task<SettingsMessage> {
        match message {
            SettingsMessage::PositionSelected(position) => {
                self.settings.tab_bar_position = Some(position);
                Task::none()
            }
        }
    }
}

impl Tab for SettingsTab {
    type Message = TabsMessage;

    fn tab_label(&self, _node_state: &NodeState) -> TabLabel {
        TabLabel::IconText(iced_fonts::Bootstrap::Gear.into(), String::from("Settings"))
    }

    fn content(&self, _node_state: &NodeState) -> Element<Self::Message> {
        let content: Element<SettingsMessage> = Container::new(
            Column::new().push(Text::new("Tabs position").size(20)).push(
                TabBarPosition::ALL.iter().cloned().fold(
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
                ),
            ),
        )
        .into();

        column![content.map(TabsMessage::Settings)]
            .padding(10)
            .spacing(15)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
}
