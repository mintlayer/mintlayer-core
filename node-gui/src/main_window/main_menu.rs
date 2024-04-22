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
    Color, Element, Length, Theme,
};
use iced_aw::menu::{Item, Menu, MenuBar};
use wallet_types::wallet_type::WalletType;

#[derive(Debug, Clone)]
pub enum MenuMessage {
    NoOp,
    CreateNewWallet { wallet_type: WalletType },
    RecoverWallet { wallet_type: WalletType },
    OpenWallet { wallet_type: WalletType },
    Exit,
}

pub struct MainMenu {}

impl MainMenu {
    pub fn new() -> Self {
        Self {}
    }

    pub fn view(&self) -> Element<MenuMessage> {
        let file_menu = make_menu_file();

        let menu_bar = MenuBar::new(vec![file_menu]).spacing(4.0).check_bounds_width(30.0);

        let c = iced::widget::column![container(menu_bar)];

        c.into()
    }
}

struct ButtonStyle;
impl button::StyleSheet for ButtonStyle {
    type Style = iced::Theme;

    fn active(&self, style: &Self::Style) -> button::Appearance {
        button::Appearance {
            text_color: style.extended_palette().background.base.text,
            border: iced::Border {
                radius: 4.0.into(),
                ..Default::default()
            },
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
    content: impl Into<Element<'a, MenuMessage>>,
    msg: MenuMessage,
) -> button::Button<'a, MenuMessage> {
    button(content)
        .padding([4, 8])
        .style(iced::theme::Button::Custom(Box::new(ButtonStyle {})))
        .on_press(msg)
}

fn labeled_button<'a>(label: &str, msg: MenuMessage) -> button::Button<'a, MenuMessage> {
    base_button(
        text(label)
            .width(Length::Fixed(220.0))
            .height(Length::Fixed(25.0))
            .vertical_alignment(alignment::Vertical::Center),
        msg,
    )
}

fn menu_item(label: &str, msg: MenuMessage) -> Item<'_, MenuMessage, Theme, iced::Renderer> {
    Item::new(labeled_button(label, msg).width(Length::Fixed(230.0)))
}

fn make_menu_file<'a>() -> Item<'a, MenuMessage, Theme, iced::Renderer> {
    let root = Item::with_menu(
        labeled_button("File", MenuMessage::NoOp),
        Menu::new(vec![
            menu_item(
                "Create new Hot wallet",
                MenuMessage::CreateNewWallet {
                    wallet_type: WalletType::Hot,
                },
            ),
            menu_item(
                "Create new Cold wallet",
                MenuMessage::CreateNewWallet {
                    wallet_type: WalletType::Cold,
                },
            ),
            menu_item(
                "Recover Hot wallet",
                MenuMessage::RecoverWallet {
                    wallet_type: WalletType::Hot,
                },
            ),
            menu_item(
                "Recover Cold wallet",
                MenuMessage::RecoverWallet {
                    wallet_type: WalletType::Cold,
                },
            ),
            menu_item(
                "Open Hot wallet",
                MenuMessage::OpenWallet {
                    wallet_type: WalletType::Hot,
                },
            ),
            menu_item(
                "Open Cold wallet",
                MenuMessage::OpenWallet {
                    wallet_type: WalletType::Cold,
                },
            ),
            // TODO: enable setting when needed
            // menu_item("Settings", MenuMessage::NoOp),
            menu_item("Exit", MenuMessage::Exit),
        ])
        .width(260),
    );

    root
}
