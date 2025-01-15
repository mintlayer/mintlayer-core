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
    widget::{container, text_input, Button, Text},
    Length,
};
use iced_aw::Card;

pub fn new_wallet_account<'a, Message: Clone + 'a, F: Fn(String) -> Message + 'a>(
    name: &'a str,
    on_submit: Message,
    on_change: F,
    on_close: Message,
) -> Card<'a, Message> {
    let button = Button::new(Text::new("Create").align_x(Horizontal::Center))
        .width(100.0)
        .on_press(on_submit);

    Card::new(
        Text::new("New account"),
        iced::widget::column![text_input("Account name", name).on_input(on_change).padding(15)],
    )
    .foot(container(button).center_x(Length::Fill))
    .max_width(600.0)
    .on_close(on_close)
}
