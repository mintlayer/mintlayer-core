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
    widget::{container, text_input, Button, Text},
    Length,
};
use iced_aw::Card;

pub fn wallet_set_password_dialog<'a, Message, F1, F2>(
    state: &SetPasswordState,
    on_set_password: Message,
    on_edit_password1: F1,
    on_edit_password2: F2,
    on_close: Message,
) -> Card<'a, Message>
where
    Message: Clone + 'a,
    F1: Fn(String) -> Message + 'a,
    F2: Fn(String) -> Message + 'a,
{
    let button_enabled = !state.password1.is_empty();
    let button = Button::new(Text::new("Encrypt wallet").align_x(Horizontal::Center));
    let button = if button_enabled {
        button.on_press(on_set_password)
    } else {
        button
    };

    Card::new(
        Text::new("Encrypt wallet"),
        iced::widget::column![
            text_input("Password", &state.password1)
                .secure(true)
                .on_input(on_edit_password1)
                .padding(15),
            text_input("Repeat", &state.password2)
                .secure(true)
                .on_input(on_edit_password2)
                .padding(15)
        ]
        .spacing(10),
    )
    .foot(container(button).center_x(Length::Fill))
    .max_width(600.0)
    .on_close(on_close)
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct SetPasswordState {
    pub password1: String,
    pub password2: String,
}
