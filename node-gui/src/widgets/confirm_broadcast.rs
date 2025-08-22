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

use std::sync::Arc;

#[allow(deprecated)]
use iced::widget::Component;

use iced::{
    alignment::Horizontal,
    widget::{self, container, Button, Text},
    Element, Length, Theme,
};
use iced_aw::Card;

use common::chain::ChainConfig;
use node_gui_backend::messages::SignedTransactionWrapper;

pub struct ConfirmBroadcast<Message> {
    on_submit: Box<dyn Fn(SignedTransactionWrapper) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy_to_clipboard: Box<dyn Fn(String) -> Message>,
    tx: SignedTransactionWrapper,
    chain_config: Arc<ChainConfig>,
}

pub fn new_confirm_broadcast<Message>(
    on_submit: Box<dyn Fn(SignedTransactionWrapper) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy_to_clipboard: Box<dyn Fn(String) -> Message>,
    tx: SignedTransactionWrapper,
    chain_config: Arc<ChainConfig>,
) -> ConfirmBroadcast<Message> {
    ConfirmBroadcast {
        on_submit,
        on_close,
        on_copy_to_clipboard,
        tx,
        chain_config,
    }
}

#[derive(Default)]
pub struct ConfirmBroadcastState {}

#[derive(Clone)]
pub enum ConfirmBroadcastEvent {
    Ok,
    Cancel,
    CopyToClipboard(String),
}

#[allow(deprecated)]
impl<Message> Component<Message, Theme, iced::Renderer> for ConfirmBroadcast<Message> {
    type State = ConfirmBroadcastState;
    type Event = ConfirmBroadcastEvent;

    fn update(&mut self, _state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            ConfirmBroadcastEvent::Ok => Some((self.on_submit)(self.tx.clone())),
            ConfirmBroadcastEvent::Cancel => Some((self.on_close)()),
            ConfirmBroadcastEvent::CopyToClipboard(text) => Some((self.on_copy_to_clipboard)(text)),
        }
    }

    fn view(&self, _state: &Self::State) -> Element<'_, Self::Event, Theme, iced::Renderer> {
        let summary = self.tx.text_summary(&self.chain_config);

        let button = Button::new(Text::new("Confirm and broadcast").align_x(Horizontal::Center))
            .width(220.0)
            .on_press(ConfirmBroadcastEvent::Ok);

        let copy_to_clipboard = Button::new(
            Text::new(iced_fonts::Bootstrap::ClipboardCheck.to_string())
                .font(iced_fonts::BOOTSTRAP_FONT),
        )
        .style(iced::widget::button::text)
        .on_press(ConfirmBroadcastEvent::CopyToClipboard(summary.clone()));

        Card::new(
            Text::new("Confirm submit transaction"),
            iced::widget::column![iced::widget::text(summary).font(iced::font::Font {
                family: iced::font::Family::Monospace,
                weight: Default::default(),
                stretch: Default::default(),
                style: iced::font::Style::Normal,
            }),],
        )
        .foot(
            container(iced::widget::row![
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                container(button).center_x(Length::Shrink),
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                container(copy_to_clipboard).align_x(Horizontal::Right)
            ])
            .width(Length::Fill),
        )
        .max_width(1200.0)
        .on_close(ConfirmBroadcastEvent::Cancel)
        .into()
    }
}

impl<'a, Message> From<ConfirmBroadcast<Message>> for Element<'a, Message, Theme, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: ConfirmBroadcast<Message>) -> Self {
        #[allow(deprecated)]
        widget::component(component)
    }
}
