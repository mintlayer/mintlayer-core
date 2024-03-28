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
    alignment::Horizontal,
    widget::{self, container, text_input, Button, Component, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct NewWalletAccount<Message> {
    on_submit: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
}

pub fn new_wallet_account<Message>(
    on_submit: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
) -> NewWalletAccount<Message> {
    NewWalletAccount {
        on_submit,
        on_close,
    }
}

#[derive(Default)]
pub struct NewAccountState {
    name: String,
}

#[derive(Clone)]
pub enum NewAccountEvent {
    EditName(String),
    Ok,
    Cancel,
}

impl<Message> Component<Message, Theme, iced::Renderer> for NewWalletAccount<Message> {
    type State = NewAccountState;
    type Event = NewAccountEvent;

    fn update(&mut self, state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            NewAccountEvent::EditName(password) => {
                state.name = password;
                None
            }
            NewAccountEvent::Ok => Some((self.on_submit)(state.name.clone())),
            NewAccountEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, state: &Self::State) -> Element<Self::Event, Theme, iced::Renderer> {
        let button = Button::new(Text::new("Create").horizontal_alignment(Horizontal::Center))
            .width(100.0)
            .on_press(NewAccountEvent::Ok);

        Card::new(
            Text::new("New account"),
            iced::widget::column![text_input("Account name", &state.name)
                .on_input(NewAccountEvent::EditName)
                .padding(15)],
        )
        .foot(container(button).width(Length::Fill).center_x())
        .max_width(600.0)
        .on_close(NewAccountEvent::Cancel)
        .into()
    }
}

impl<'a, Message> From<NewWalletAccount<Message>> for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: NewWalletAccount<Message>) -> Self {
        widget::component(component)
    }
}
