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
    widget::{button, column, row, scrollable::Id, tooltip, Scrollable, Text},
    Element, Length,
};

use node_gui_backend::messages::WalletInfo;

use crate::main_window::main_widget::tabs::wallet::{
    status_bar::estimate_status_bar_height, STATUS_BAR_SEPARATOR_HEIGHT,
};

use super::{ConsoleState, WalletMessage};

const SUBMIT_TOOLTIP_TEXT: &str = "Submit the provided command to be processed";
pub const CONSOLE_OUTPUT_ID: &str = "console_input_id";

pub fn view_console(
    state: &ConsoleState,
    still_syncing: Option<WalletMessage>,
    wallet_info: &WalletInfo,
) -> Element<'static, WalletMessage> {
    let s: Vec<String> = state
        .console_inputs
        .iter()
        .zip(&state.console_outputs)
        .map(|(inp, out)| format!("> {inp}\n$ {out}"))
        .collect();

    let output = s.join("\n");
    // Note: it doesn't seem possible to make Scrollable fill the entire parent container,
    // e.g. passing Length::Fill for height will result in a panic:
    // "scrollable content must not fill its vertical scrolling axis".
    // So we have to use a fixed height. The value is chosen such that when the main window
    // has the initial height, the console widget fills the entire area of its parent.
    // But we also have to take the status bar into account.
    #[allow(clippy::float_arithmetic)]
    let height = {
        let status_bar_height =
            estimate_status_bar_height(&wallet_info.extra_info) + STATUS_BAR_SEPARATOR_HEIGHT;
        Length::Fixed(570.0 - status_bar_height)
    };
    let console_output = Scrollable::new(iced::widget::text(output.clone()))
        .height(height)
        .width(Length::Fill)
        .id(Id::new(CONSOLE_OUTPUT_ID));

    let console_input = iced::widget::text_input("command", &state.console_input)
        .on_input(WalletMessage::ConsoleInputChange)
        .on_submit(WalletMessage::ConsoleInputSubmit);

    let buttons = row![
        iced::widget::horizontal_space(),
        button(
            Text::new(iced_fonts::Bootstrap::ClipboardCheck.to_string())
                .font(iced_fonts::BOOTSTRAP_FONT),
        )
        .style(iced::widget::button::text)
        .width(Length::Shrink)
        .on_press(WalletMessage::CopyToClipboard(output)),
        button(
            Text::new(iced_fonts::Bootstrap::Trash.to_string()).font(iced_fonts::BOOTSTRAP_FONT),
        )
        .style(iced::widget::button::text)
        .width(Length::Shrink)
        .on_press(WalletMessage::ConsoleClear),
    ]
    .width(Length::Fill)
    .align_y(iced::Alignment::End);

    column![
        buttons,
        console_output,
        row![
            console_input,
            iced::widget::button(Text::new("Submit"))
                .on_press(still_syncing.unwrap_or(WalletMessage::ConsoleInputSubmit)),
            tooltip(
                Text::new(iced_fonts::Bootstrap::Question.to_string())
                    .font(iced_fonts::BOOTSTRAP_FONT),
                SUBMIT_TOOLTIP_TEXT,
                tooltip::Position::Bottom
            )
            .gap(10)
            .style(iced::widget::container::bordered_box),
        ],
    ]
    .into()
}
