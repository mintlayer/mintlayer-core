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
    widget::{self, container, text_input, Button, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct WalletUnlockDialog<Message> {
    on_set_password: Box<dyn Fn(String, String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
}

pub fn wallet_set_password_dialog<Message>(
    on_set_password: Box<dyn Fn(String, String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
) -> WalletUnlockDialog<Message> {
    WalletUnlockDialog {
        on_set_password,
        on_close,
    }
}

#[derive(Default)]
pub struct SetPasswordState {
    password1: String,
    password2: String,
}

#[derive(Clone)]
pub enum SetPasswordEvent {
    EditPassword1(String),
    EditPassword2(String),
    Ok,
    Cancel,
}

#[allow(deprecated)]
impl<Message> Component<Message, Theme, iced::Renderer> for WalletUnlockDialog<Message> {
    type State = SetPasswordState;
    type Event = SetPasswordEvent;

    fn update(&mut self, state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            SetPasswordEvent::EditPassword1(password) => {
                state.password1 = password;
                None
            }
            SetPasswordEvent::EditPassword2(password) => {
                state.password2 = password;
                None
            }
            SetPasswordEvent::Ok => Some((self.on_set_password)(
                state.password1.clone(),
                state.password2.clone(),
            )),
            SetPasswordEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, state: &Self::State) -> Element<'_, Self::Event, Theme, iced::Renderer> {
        let button_enabled = !state.password1.is_empty();
        let button = Button::new(Text::new("Encrypt wallet").align_x(Horizontal::Center));
        let button = if button_enabled {
            button.on_press(SetPasswordEvent::Ok)
        } else {
            button
        };

        Card::new(
            Text::new("Encrypt wallet"),
            iced::widget::column![
                text_input("Password", &state.password1)
                    .secure(true)
                    .on_input(SetPasswordEvent::EditPassword1)
                    .padding(15),
                text_input("Repeat", &state.password2)
                    .secure(true)
                    .on_input(SetPasswordEvent::EditPassword2)
                    .padding(15)
            ]
            .spacing(10),
        )
        .foot(container(button).center_x(Length::Fill))
        .max_width(600.0)
        .on_close(SetPasswordEvent::Cancel)
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
