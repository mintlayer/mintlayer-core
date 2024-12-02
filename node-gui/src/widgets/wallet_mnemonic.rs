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
    widget::{self, container, text, text_input, Button, Component, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct WalletMnemonicDialog<Message> {
    generated_mnemonic_opt: Option<String>,
    on_import: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
}

pub fn wallet_mnemonic_dialog<Message>(
    generated_mnemonic_opt: Option<String>,
    on_import: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
) -> WalletMnemonicDialog<Message> {
    WalletMnemonicDialog {
        generated_mnemonic_opt,
        on_import,
        on_close,
    }
}

#[derive(Default)]
pub struct ImportState {
    entered_mnemonic: String,
    importing: bool,
}

#[derive(Clone)]
pub enum ImportEvent {
    EditMnemonic(String),
    Ok,
    Cancel,
}

impl<Message> Component<Message, Theme, iced::Renderer> for WalletMnemonicDialog<Message> {
    type State = ImportState;
    type Event = ImportEvent;

    fn update(&mut self, state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            ImportEvent::EditMnemonic(mnemonic) => {
                match &self.generated_mnemonic_opt {
                    Some(_generated_mnemonic) => {}
                    None => state.entered_mnemonic = mnemonic,
                }
                None
            }
            ImportEvent::Ok => {
                state.importing = true;
                let mnemonic = match &self.generated_mnemonic_opt {
                    Some(generated_mnemonic) => generated_mnemonic.clone(),
                    None => state.entered_mnemonic.clone(),
                };
                Some((self.on_import)(mnemonic))
            }
            ImportEvent::Cancel => Some((self.on_close)()),
        }
    }

    fn view(&self, state: &Self::State) -> Element<Self::Event, Theme, iced::Renderer> {
        let (mnemonic, action_text) = match &self.generated_mnemonic_opt {
            Some(generated_mnemonic) => (generated_mnemonic.clone(), "Create"),
            None => (state.entered_mnemonic.clone(), "Recover"),
        };

        let button_enabled = !mnemonic.is_empty();
        let button = Button::new(Text::new(action_text).horizontal_alignment(Horizontal::Center))
            .width(100.0);
        let button = if button_enabled {
            button.on_press(ImportEvent::Ok)
        } else {
            button
        };

        if state.importing {
            Card::new(
                Text::new(action_text),
                iced::widget::column![text_input("Mnemonic", &mnemonic).padding(15)],
            )
            .foot(container(text("Loading...")).width(Length::Fill).center_x())
        } else {
            Card::new(
                Text::new(action_text),
                iced::widget::column![text_input("Mnemonic", &mnemonic)
                    .on_input(ImportEvent::EditMnemonic)
                    .padding(15)],
            )
            .foot(container(button).width(Length::Fill).center_x())
        }
        .max_width(600.0)
        .on_close(ImportEvent::Cancel)
        .into()
    }
}

impl<'a, Message> From<WalletMnemonicDialog<Message>>
    for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: WalletMnemonicDialog<Message>) -> Self {
        widget::component(component)
    }
}
