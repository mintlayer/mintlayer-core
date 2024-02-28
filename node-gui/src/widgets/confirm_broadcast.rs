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

use common::{
    chain::{ChainConfig, SignedTransaction},
    text_summary::TextSummary,
};
use iced::{
    alignment::Horizontal,
    widget::{self, container, Button, Component, Text},
    Element, Length,
};
use iced_aw::Card;

pub struct ConfirmBroadcast<Message> {
    on_submit: Box<dyn Fn(SignedTransaction) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy_to_clipboard: Box<dyn Fn(String) -> Message>,
    tx: SignedTransaction,
    chain_config: Arc<ChainConfig>,
}

pub fn new_confirm_broadcast<Message>(
    on_submit: Box<dyn Fn(SignedTransaction) -> Message>,
    on_close: Box<dyn Fn() -> Message>,
    on_copy_to_clipboard: Box<dyn Fn(String) -> Message>,
    tx: SignedTransaction,
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

impl<Message> Component<Message, iced::Renderer> for ConfirmBroadcast<Message> {
    type State = ConfirmBroadcastState;
    type Event = ConfirmBroadcastEvent;

    fn update(&mut self, _state: &mut Self::State, event: Self::Event) -> Option<Message> {
        match event {
            ConfirmBroadcastEvent::Ok => Some((self.on_submit)(self.tx.clone())),
            ConfirmBroadcastEvent::Cancel => Some((self.on_close)()),
            ConfirmBroadcastEvent::CopyToClipboard(text) => Some((self.on_copy_to_clipboard)(text)),
        }
    }

    fn view(&self, _state: &Self::State) -> Element<Self::Event, iced::Renderer> {
        let summary = self.tx.transaction().text_summary(&self.chain_config);

        let button = Button::new(
            Text::new("Confirm and broadcast").horizontal_alignment(Horizontal::Center),
        )
        .width(220.0)
        .on_press(ConfirmBroadcastEvent::Ok);

        let copy_to_clipboard = Button::new(
            Text::new(iced_aw::Icon::ClipboardCheck.to_string()).font(iced_aw::ICON_FONT),
        )
        .style(iced::theme::Button::Text)
        .on_press(ConfirmBroadcastEvent::CopyToClipboard(summary.clone()));

        Card::new(
            Text::new("Confirm submit transaction"),
            iced::widget::column![iced::widget::text(summary).font(iced::font::Font {
                family: iced::font::Family::Monospace,
                weight: Default::default(),
                stretch: Default::default(),
                monospaced: true
            }),],
        )
        .foot(
            container(iced::widget::row![
                iced::widget::Space::new(Length::Fill, Length::Shrink),
                container(button).center_x(),
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

impl<'a, Message> From<ConfirmBroadcast<Message>> for Element<'a, Message, iced::Renderer>
where
    Message: 'a,
{
    fn from(component: ConfirmBroadcast<Message>) -> Self {
        widget::component(component)
    }
}
