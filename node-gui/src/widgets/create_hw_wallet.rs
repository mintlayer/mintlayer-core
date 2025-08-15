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

#[allow(deprecated)]
use iced::widget::Component;

use iced::{
    alignment::Horizontal,
    widget::{self, container, text, Button, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

use wallet_types::ImportOrCreate;

pub struct CreateHwWalletDialog<Message> {
    on_import: Box<dyn Fn() -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    mode: ImportOrCreate,
}

pub fn hw_wallet_create_dialog<Message>(
    on_import: Box<dyn Fn() -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    mode: ImportOrCreate,
) -> CreateHwWalletDialog<Message> {
    CreateHwWalletDialog {
        on_import,
        on_close,
        mode,
    }
}

#[derive(Default)]
pub struct ImportState {
    importing: bool,
}

#[derive(Clone)]
pub enum ImportEvent {
    Ok,
    Cancel,
}

#[allow(deprecated)]
impl<Message> Component<Message, Theme, iced::Renderer> for CreateHwWalletDialog<Message> {
    type State = ImportState;
    type Event = ImportEvent;

    fn update(&mut self, state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            ImportEvent::Ok => {
                state.importing = true;
                Some((self.on_import)())
            }
            ImportEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, state: &Self::State) -> Element<Self::Event, Theme, iced::Renderer> {
        let button = Button::new(Text::new("Select file").align_x(Horizontal::Center))
            .width(100.0)
            .on_press(ImportEvent::Ok);

        let card = match self.mode {
            ImportOrCreate::Create => Card::new(
                Text::new("Create new Wallet"),
                Text::new("Create a new Trezor wallet using the connected Trezor device"),
            ),
            ImportOrCreate::Import => Card::new(
                Text::new("Recover new Wallet"),
                Text::new("Recover a new wallet using the connected Trezor device"),
            ),
        };
        if state.importing {
            card.foot(container(text("Loading...")).center_x(Length::Fill))
        } else {
            card.foot(container(button).center_x(Length::Fill))
                .on_close(ImportEvent::Cancel)
        }
        .max_width(600.0)
        .into()
    }
}

impl<'a, Message> From<CreateHwWalletDialog<Message>>
    for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: CreateHwWalletDialog<Message>) -> Self {
        #[allow(deprecated)]
        widget::component(component)
    }
}
