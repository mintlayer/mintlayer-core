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
    alignment,
    widget::{button, container, text},
    Color, Command, Element, Length,
};
use iced_aw::menu::{CloseCondition, ItemHeight, ItemWidth, MenuBar, MenuTree, PathHighlight};

use crate::{backend_controller::NodeBackendController, Message};

#[derive(Debug, Clone)]
pub enum MenuMessage {
    NoOp,
    Exit,
}

impl From<MenuMessage> for Message {
    fn from(msg: MenuMessage) -> Self {
        Message::MenuMessage(msg)
    }
}

struct ButtonStyle;
impl button::StyleSheet for ButtonStyle {
    type Style = iced::Theme;

    fn active(&self, style: &Self::Style) -> button::Appearance {
        button::Appearance {
            text_color: style.extended_palette().background.base.text,
            border_radius: 4.0,
            background: Some(Color::TRANSPARENT.into()),
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Appearance {
        let plt = style.extended_palette();

        button::Appearance {
            background: Some(plt.primary.weak.color.into()),
            text_color: plt.primary.weak.text,
            ..self.active(style)
        }
    }
}

fn base_button<'a>(
    content: impl Into<Element<'a, Message, iced::Renderer>>,
    msg: Message,
) -> button::Button<'a, Message, iced::Renderer> {
    button(content)
        .padding([4, 8])
        .style(iced::theme::Button::Custom(Box::new(ButtonStyle {})))
        .on_press(msg)
}

fn labeled_button<'a>(label: &str, msg: Message) -> button::Button<'a, Message, iced::Renderer> {
    base_button(
        text(label)
            .width(Length::Fill)
            .height(Length::Fill)
            .vertical_alignment(alignment::Vertical::Center),
        msg,
    )
}

fn menu_item<'a>(label: &str, msg: Message) -> MenuTree<'a, Message, iced::Renderer> {
    MenuTree::new(labeled_button(label, msg).width(Length::Fill).height(Length::Fill))
}

fn make_menu_file<'a>() -> MenuTree<'a, Message, iced::Renderer> {
    let root = MenuTree::with_children(
        labeled_button("File", Message::MenuMessage(MenuMessage::NoOp)),
        vec![
            menu_item("Settings", Message::MenuMessage(MenuMessage::NoOp)),
            menu_item("Exit", Message::MenuMessage(MenuMessage::Exit)),
        ],
    )
    .width(110);

    root
}

fn make_menu_help<'a>() -> MenuTree<'a, Message, iced::Renderer> {
    let root = MenuTree::with_children(
        labeled_button("Help", Message::MenuMessage(MenuMessage::NoOp)),
        vec![menu_item("About", Message::MenuMessage(MenuMessage::NoOp))],
    )
    .width(110);

    root
}

pub fn view<'a>(
    backend_controller: &NodeBackendController,
) -> Element<'a, Message, iced::Renderer> {
    let file_menu = make_menu_file();
    let help_menu = make_menu_help();

    let menu_bar = MenuBar::new(vec![file_menu, help_menu])
        .item_width(ItemWidth::Uniform(180))
        .item_height(ItemHeight::Uniform(25))
        .spacing(4.0)
        .bounds_expand(30)
        .path_highlight(Some(PathHighlight::MenuActive))
        .close_condition(CloseCondition {
            leave: true,
            click_outside: false,
            click_inside: false,
        });

    let main_widget = text(&format!(
        "Genesis block: {}",
        backend_controller.chain_config().genesis_block_id(),
    ))
    .width(Length::Fill)
    .size(25)
    .horizontal_alignment(alignment::Horizontal::Center)
    .vertical_alignment(alignment::Vertical::Center);

    let c = iced::widget::column![container(menu_bar), container(main_widget)];

    c.into()
}

pub fn message_to_action(msg: MenuMessage) -> Command<Message> {
    match msg {
        MenuMessage::NoOp => Command::none(),
        MenuMessage::Exit => iced::window::close(),
    }
}
