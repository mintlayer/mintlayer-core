// Copyright (c) 2021-2024 RBB S.r.l
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
    alignment::Horizontal,
    widget::{self, container, Button, Component, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct CreateHwWalletDialog<Message> {
    on_import: Box<dyn Fn() -> Message>,
    on_close: Box<dyn Fn() -> Message>,
}

pub fn hw_wallet_create_dialog<Message>(
    on_import: Box<dyn Fn() -> Message>,
    on_close: Box<dyn Fn() -> Message>,
) -> CreateHwWalletDialog<Message> {
    CreateHwWalletDialog {
        on_import,
        on_close,
    }
}

#[derive(Clone)]
pub enum ImportEvent {
    Ok,
    Cancel,
}

impl<Message> Component<Message, Theme, iced::Renderer> for CreateHwWalletDialog<Message> {
    type State = ();
    type Event = ImportEvent;

    fn update(&mut self, _state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            ImportEvent::Ok => Some((self.on_import)()),
            ImportEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, _state: &Self::State) -> Element<Self::Event, Theme, iced::Renderer> {
        let button = Button::new(Text::new("Select file").horizontal_alignment(Horizontal::Center))
            .width(100.0)
            .on_press(ImportEvent::Ok);

        Card::new(
            Text::new("Create new Wallet"),
            Text::new("Create a new Trezor wallet using the connected Trezor device"),
        )
        .foot(container(button).width(Length::Fill).center_x())
        .max_width(600.0)
        .on_close(ImportEvent::Cancel)
        .into()
    }
}

impl<'a, Message> From<CreateHwWalletDialog<Message>>
    for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: CreateHwWalletDialog<Message>) -> Self {
        widget::component(component)
    }
}
