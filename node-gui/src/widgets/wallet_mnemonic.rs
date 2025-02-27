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

#[allow(deprecated)]
use iced::widget::Component;

use iced::{
    alignment::Horizontal,
    widget::{self, container, text, text_input, Button, Row, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

pub struct WalletMnemonicDialog<Message> {
    generated_mnemonic_opt: Option<String>,
    on_import: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy: Box<dyn Fn(String) -> Message>,
}

pub fn wallet_mnemonic_dialog<Message: Clone>(
    generated_mnemonic_opt: Option<String>,
    on_import: Box<dyn Fn(String) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy: Box<dyn Fn(String) -> Message>,
) -> WalletMnemonicDialog<Message> {
    WalletMnemonicDialog {
        generated_mnemonic_opt,
        on_import,
        on_close,
        on_copy,
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
    CopyMnemonic(String),
    Ok,
    Cancel,
}

#[allow(deprecated)]
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
            ImportEvent::CopyMnemonic(mnemonic) => Some((self.on_copy)(mnemonic)),
        }
    }

    fn view(&self, state: &Self::State) -> Element<Self::Event, Theme, iced::Renderer> {
        let (mnemonic, action_text) = match &self.generated_mnemonic_opt {
            Some(generated_mnemonic) => (generated_mnemonic.clone(), "Create"),
            None => (state.entered_mnemonic.clone(), "Recover"),
        };

        let button_enabled = !mnemonic.is_empty();

        // only enable edit if there is not pre-generated mnemonic
        let body: Element<_> = if self.generated_mnemonic_opt.is_none() {
            text_input("Mnemonic", &mnemonic)
                .on_input(ImportEvent::EditMnemonic)
                .padding(15)
                .into()
        } else {
            Row::new()
                .push(text(mnemonic.clone()).width(Length::Fill).center())
                .push(
                    Button::new(
                        Text::new(iced_fonts::Bootstrap::ClipboardCheck.to_string())
                            .font(iced_fonts::BOOTSTRAP_FONT)
                            .size(30),
                    )
                    .style(iced::widget::button::text)
                    .on_press(ImportEvent::CopyMnemonic(mnemonic)),
                )
                .spacing(10)
                .padding(15)
                .into()
        };

        let footer = if state.importing {
            container(text("Loading..."))
        } else {
            let button =
                Button::new(Text::new(action_text).align_x(Horizontal::Center)).width(100.0);
            let button = if button_enabled {
                button.on_press(ImportEvent::Ok)
            } else {
                button
            };
            container(button)
        }
        .center_x(Length::Fill);

        let card = Card::new(Text::new(action_text), body).foot(footer).max_width(600.0);

        if state.importing {
            card
        } else {
            card.on_close(ImportEvent::Cancel)
        }
        .into()
    }
}

impl<'a, Message> From<WalletMnemonicDialog<Message>>
    for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: WalletMnemonicDialog<Message>) -> Self {
        #[allow(deprecated)]
        widget::component(component)
    }
}
