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

use crate::WalletMode;

#[derive(Debug, Clone)]
pub enum MenuMessage {
    NoOp,
    CreateNewWallet { wallet_type: WalletType },
    RecoverWallet { wallet_type: WalletType },
    OpenWallet { wallet_type: WalletType },
    Exit,
}

pub struct MainMenu {
    wallet_mode: WalletMode,
}

impl MainMenu {
    pub fn new(wallet_mode: WalletMode) -> Self {
        Self { wallet_mode }
    }

    pub fn view(&self) -> Element<MenuMessage> {
        let file_menu = make_menu_file(self.wallet_mode);

        let menu_bar = MenuBar::new(vec![file_menu]).spacing(4.0).check_bounds_width(30.0);

        let c = iced::widget::column![container(menu_bar)];

        c.into()
    }
}

fn base_button<'a>(
    content: impl Into<Element<'a, MenuMessage>>,
    msg: MenuMessage,
) -> button::Button<'a, MenuMessage> {
    button(content)
        .padding([4, 8])
        .style(|theme, status| {
            let plt = theme.extended_palette();
            match status {
                button::Status::Active => button::Style {
                    text_color: plt.background.base.text,
                    border: iced::Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    background: Some(Color::TRANSPARENT.into()),
                    ..Default::default()
                },
                button::Status::Hovered => button::Style {
                    text_color: plt.primary.weak.text,
                    background: Some(plt.primary.weak.color.into()),
                    border: iced::Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                button::Status::Pressed | button::Status::Disabled => button::Style::default(),
            }
        })
        .on_press(msg)
}

fn labeled_button<'a>(label: &'a str, msg: MenuMessage) -> button::Button<'a, MenuMessage> {
    base_button::<'a>(
        text(label)
            .width(Length::Fixed(220.0))
            .height(Length::Fixed(25.0))
            .align_y(alignment::Vertical::Center),
        msg,
    )
}

fn menu_item(label: &str, msg: MenuMessage) -> Item<'_, MenuMessage, Theme, iced::Renderer> {
    Item::new(labeled_button(label, msg).width(Length::Fixed(230.0)))
}

fn make_menu_file<'a>(wallet_mode: WalletMode) -> Item<'a, MenuMessage, Theme, iced::Renderer> {
    let root = Item::with_menu(
        labeled_button("File", MenuMessage::NoOp),
        Menu::new(match wallet_mode {
            WalletMode::Hot => {
                vec![
                    menu_item(
                        "Create new Hot wallet",
                        MenuMessage::CreateNewWallet {
                            wallet_type: WalletType::Hot,
                        },
                    ),
                    menu_item(
                        "Recover Hot wallet",
                        MenuMessage::RecoverWallet {
                            wallet_type: WalletType::Hot,
                        },
                    ),
                    menu_item(
                        "Open Hot wallet",
                        MenuMessage::OpenWallet {
                            wallet_type: WalletType::Hot,
                        },
                    ),
                    // TODO: enable setting when needed
                    // menu_item("Settings", MenuMessage::NoOp),
                    menu_item("Exit", MenuMessage::Exit),
                ]
            }
            WalletMode::Cold => {
                vec![
                    menu_item(
                        "Create new Cold wallet",
                        MenuMessage::CreateNewWallet {
                            wallet_type: WalletType::Cold,
                        },
                    ),
                    menu_item(
                        "Recover Cold wallet",
                        MenuMessage::RecoverWallet {
                            wallet_type: WalletType::Cold,
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
                ]
            }
            WalletMode::Trezor => {
                vec![
                    menu_item(
                        "Create new Trezor wallet",
                        MenuMessage::CreateNewWallet {
                            wallet_type: WalletType::Trezor,
                        },
                    ),
                    menu_item(
                        "Open Trezor wallet",
                        MenuMessage::OpenWallet {
                            wallet_type: WalletType::Trezor,
                        },
                    ),
                    // TODO: enable setting when needed
                    // menu_item("Settings", MenuMessage::NoOp),
                    menu_item("Exit", MenuMessage::Exit),
                ]
            }
        })
        .width(260),
    );

    root
}
