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
    widget::{container, text, text_input, Button, Text},
    Length,
};
use iced_aw::Card;

pub fn wallet_unlock_dialog<'a, Message, F>(
    state: &UnlockState,
    on_edit_password: F,
    on_unlock: Message,
    on_close: Message,
) -> Card<'a, Message>
where
    Message: Clone + 'a,
    F: Fn(String) -> Message + 'a,
{
    let container = match state.unlocking {
        true => container(text("Unlocking...")),
        false => {
            let button_enabled = !state.password.is_empty();
            let button = Button::new(Text::new("Unlock").align_x(Horizontal::Center))
                .width(100.0)
                .on_press_maybe(button_enabled.then_some(on_unlock));
            container(button)
        }
    };

    let password = text_input("Password", &state.password)
        .secure(true)
        .on_input_maybe((!state.unlocking).then_some(on_edit_password));

    Card::new(
        Text::new("Unlock"),
        iced::widget::column![password.padding(15)],
    )
    .foot(container.center_x(Length::Fill))
    .max_width(600.0)
    .on_close(on_close)
}

#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub struct UnlockState {
    pub password: String,
    pub unlocking: bool,
}

impl UnlockState {
    pub fn with_changed_password(&self, password: String) -> Self {
        Self {
            password,
            unlocking: self.unlocking,
        }
    }
}
