// Copyright (c) 2024 RBB S.r.l
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
    widget::{column, container, row, scrollable::Id, tooltip, Scrollable, Text},
    Element, Length,
};

use super::{ConsoleState, WalletMessage};

const SUBMIT_TOOLTIP_TEXT: &str = "Submit the provided command to be processed";
pub const CONSOLE_OUTPUT_ID: &str = "console_input_id";

pub fn view_console(
    state: &ConsoleState,
    console_outputs: &Vec<String>,
    still_syncing: Option<WalletMessage>,
) -> Element<'static, WalletMessage> {
    let title = container(Text::new("Console:")).padding(5);

    let s: Vec<String> = state
        .console_outputs
        .iter()
        .zip(console_outputs)
        .map(|(inp, out)| format!("> {inp}\n$ {out}"))
        .collect();

    let output = s.join("\n");
    let console_output = Scrollable::new(iced::widget::text(output))
        .height(Length::Fixed(350.0))
        .width(Length::Fill)
        .id(Id::new(CONSOLE_OUTPUT_ID));

    let console_input = iced::widget::text_input("command", &state.console_input)
        .on_input(WalletMessage::ConsoleInputChange)
        .on_submit(WalletMessage::ConsoleInputSubmit);

    column![
        title,
        console_output,
        row![
            console_input,
            iced::widget::button(Text::new("Submit"))
                .on_press(still_syncing.unwrap_or(WalletMessage::ConsoleInputSubmit)),
            tooltip(
                Text::new(iced_aw::BootstrapIcon::Question.to_string())
                    .font(iced_aw::BOOTSTRAP_FONT),
                SUBMIT_TOOLTIP_TEXT,
                tooltip::Position::Bottom
            )
            .gap(10)
            .style(iced::theme::Container::Box)
        ],
    ]
    .into()
}
