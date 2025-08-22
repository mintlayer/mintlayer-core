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

#[allow(deprecated)]
use iced::widget::Component;

use iced::{
    alignment::Horizontal,
    widget::{self, container, text, text_input, Button, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct WalletUnlockDialog<Message> {
    on_unlock: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
}

pub fn wallet_unlock_dialog<Message>(
    on_unlock: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
) -> WalletUnlockDialog<Message> {
    WalletUnlockDialog {
        on_unlock,
        on_close,
    }
}

#[derive(Default)]
pub struct UnlockState {
    password: String,
    unlocking: bool,
}

#[derive(Clone)]
pub enum UnlockEvent {
    EditPassword(String),
    Ok,
    Cancel,
}

#[allow(deprecated)]
impl<Message> Component<Message, Theme, iced::Renderer> for WalletUnlockDialog<Message> {
    type State = UnlockState;
    type Event = UnlockEvent;

    fn update(&mut self, state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            UnlockEvent::EditPassword(password) => {
                state.password = password;
                None
            }
            UnlockEvent::Ok => {
                state.unlocking = true;
                Some((self.on_unlock)(state.password.clone()))
            }
            UnlockEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, state: &Self::State) -> Element<'_, Self::Event, Theme, iced::Renderer> {
        let container = match state.unlocking {
            true => container(text("Unlocking...")),
            false => {
                let button_enabled = !state.password.is_empty();
                let button =
                    Button::new(Text::new("Unlock").align_x(Horizontal::Center)).width(100.0);
                let button = if button_enabled {
                    button.on_press(UnlockEvent::Ok)
                } else {
                    button
                };
                container(button)
            }
        };

        let password = text_input("Password", &state.password).secure(true);
        let password = match state.unlocking {
            true => password,
            false => password.on_input(UnlockEvent::EditPassword),
        };

        Card::new(
            Text::new("Unlock"),
            iced::widget::column![password.padding(15)],
        )
        .foot(container.center_x(Length::Fill))
        .max_width(600.0)
        .on_close(UnlockEvent::Cancel)
        .into()
    }
}

impl<'a, Message> From<WalletUnlockDialog<Message>> for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: WalletUnlockDialog<Message>) -> Self {
        #[allow(deprecated)]
        widget::component(component)
    }
}
