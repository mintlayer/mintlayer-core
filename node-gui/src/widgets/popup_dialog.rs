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
    widget::{self, container, Button, Component, Text},
    Element, Length,
};
use iced_aw::Card;

#[derive(Clone)]
pub struct Popup {
    pub title: String,
    pub message: String,
}

pub struct PopupDialog<Message> {
    pub popup: Popup,
    pub on_close: Message,
}

pub fn popup_dialog<Message>(popup: Popup, on_close: Message) -> PopupDialog<Message> {
    PopupDialog { popup, on_close }
}

impl<Message: Clone> Component<Message, iced::Renderer> for PopupDialog<Message> {
    type State = ();
    type Event = ();

    fn update(&mut self, _state: &mut Self::State, _event: Self::Event) -> Option<Message> {
        Some(self.on_close.clone())
    }

    fn view(&self, _state: &Self::State) -> Element<Self::Event, iced::Renderer> {
        Card::new(
            Text::new(self.popup.title.clone()),
            Text::new(self.popup.message.clone()).horizontal_alignment(Horizontal::Center),
        )
        .foot(
            container(
                Button::new(Text::new("Ok").horizontal_alignment(Horizontal::Center))
                    .width(100.0)
                    .on_press(()),
            )
            .width(Length::Fill)
            .center_x(),
        )
        .max_width(300.0)
        .on_close(())
        .into()
    }
}

impl<'a, Message: Clone> From<PopupDialog<Message>> for Element<'a, Message, iced::Renderer>
where
    Message: 'a,
{
    fn from(my_component: PopupDialog<Message>) -> Self {
        widget::component(my_component)
    }
}
