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
    alignment::Horizontal,
    widget::{container, text, text_input, Button, Text},
    Length,
};
use iced_aw::Card;

pub fn wallet_mnemonic_dialog<'a, Message, F>(
    generated_mnemonic_opt: Option<wallet_controller::mnemonic::Mnemonic>,
    state: ImportState,
    on_import: Message,
    on_mnemonic_change: F,
    on_close: Message,
) -> Card<'a, Message>
where
    Message: Clone + 'a,
    F: Fn(String) -> Message + 'a,
{
    let (mnemonic, action_text) = match &generated_mnemonic_opt {
        Some(generated_mnemonic) => (generated_mnemonic.to_string(), "Create"),
        None => (state.entered_mnemonic, "Recover"),
    };

    let button_enabled = !mnemonic.is_empty();
    let button = Button::new(Text::new(action_text).align_x(Horizontal::Center)).width(100.0);
    let button = if button_enabled {
        button.on_press(on_import)
    } else {
        button
    };
    if state.importing {
        Card::new(
            Text::new(action_text),
            iced::widget::column![text_input("Mnemonic", &mnemonic).padding(15)],
        )
        .foot(container(text("Loading...")).center_x(Length::Fill))
    } else {
        Card::new(
            Text::new(action_text),
            iced::widget::column![text_input("Mnemonic", &mnemonic)
                .on_input(on_mnemonic_change)
                .padding(15)],
        )
        .foot(container(button).center_x(Length::Fill))
    }
    .max_width(600.0)
    .on_close(on_close)
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ImportState {
    pub entered_mnemonic: String,
    importing: bool,
}

impl ImportState {
    pub fn with_changed_mnemonic(&self, new_mnemonic: String) -> Self {
        Self {
            entered_mnemonic: new_mnemonic,
            importing: self.importing,
        }
    }
}
