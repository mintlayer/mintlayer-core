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
    widget::{container, Button, Text},
    Length,
};
use iced_aw::Card;

#[derive(Clone)]
pub struct Popup {
    pub title: String,
    pub message: String,
}

pub fn popup_dialog<'a, Message: Clone + 'a>(popup: Popup, on_close: Message) -> Card<'a, Message> {
    Card::new(
        Text::new(popup.title),
        Text::new(popup.message).align_x(Horizontal::Center),
    )
    .foot(
        container(
            Button::new(Text::new("Ok").align_x(Horizontal::Center))
                .width(100.0)
                .on_press(on_close.clone()),
        )
        .center_x(Length::Fill),
    )
    .max_width(300.0)
    .on_close(on_close)
}
