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

mod backend_controller;
mod main_window;

use std::ops::DerefMut;

use backend_controller::NodeBackendController;
use iced::futures::TryFutureExt;
use iced::widget::{column, container, text};
use iced::Subscription;
use iced::{executor, Application, Command, Element, Length, Settings, Theme};
use iced_aw::native::cupertino::cupertino_spinner::CupertinoSpinner;
use main_window::MenuMessage;

pub fn main() -> iced::Result {
    MintlayerNodeGUI::run(Settings {
        antialiasing: true,
        exit_on_close_request: false,
        try_opengles_first: true,
        ..Settings::default()
    })
}

enum MintlayerNodeGUI {
    Loading,
    Loaded(NodeBackendController),
    IntializationError(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    Loaded(Result<NodeBackendController, String>),
    EventOccurred(iced::Event),
    ShuttingDownFinished,
    MenuMessage(MenuMessage),
}

fn gui_shutdown(controller: &mut NodeBackendController) -> Command<Message> {
    let manager_join_handle = match controller.trigger_shutdown() {
        Some(h) => h,
        None => return Command::none(),
    };

    Command::perform(
        async move {
            let mut handle = manager_join_handle.lock().await;
            handle.deref_mut().await.expect("Manager thread failed");
        },
        |_| Message::ShuttingDownFinished,
    )
}

impl Application for MintlayerNodeGUI {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            MintlayerNodeGUI::Loading,
            Command::perform(
                NodeBackendController::initialize().map_err(|e| e.to_string()),
                Message::Loaded,
            ),
        )
    }

    fn title(&self) -> String {
        match self {
            MintlayerNodeGUI::Loading => ("Mintlayer Node - Loading...").to_string(),
            MintlayerNodeGUI::Loaded(d) => {
                format!("Mintlayer Node - {}", d.chain_config().chain_type().name())
            }
            MintlayerNodeGUI::IntializationError(_) => "Mintlayer initialization error".to_string(),
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match self {
            MintlayerNodeGUI::Loading => match message {
                Message::Loaded(Ok(controller)) => {
                    *self = MintlayerNodeGUI::Loaded(controller);
                    Command::none()
                }
                Message::Loaded(Err(e)) => {
                    *self = MintlayerNodeGUI::IntializationError(e);
                    Command::none()
                }
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        panic!("Attempted shutdown during initialization")
                    } else {
                        // While the screen is loading, ignore all events
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => Command::none(),
                Message::MenuMessage(_) => Command::none(),
            },
            MintlayerNodeGUI::Loaded(ref mut controller) => match message {
                Message::Loaded(_) => unreachable!("Already loaded"),
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        // TODO: this event doesn't cover the case of closing the Window through Cmd+Q in MacOS
                        gui_shutdown(controller)
                    } else {
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => iced::window::close(),
                Message::MenuMessage(menu_msg) => main_window::message_to_action(menu_msg),
            },
            MintlayerNodeGUI::IntializationError(_) => match message {
                Message::Loaded(_) => Command::none(),
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        iced::window::close()
                    } else {
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => iced::window::close(),
                Message::MenuMessage(_) => Command::none(),
            },
        }
    }

    fn view(&self) -> Element<Message> {
        match self {
            MintlayerNodeGUI::Loading => {
                container(CupertinoSpinner::new().width(Length::Fill).height(Length::Fill)).into()
            }

            MintlayerNodeGUI::Loaded(_state) => main_window::view(),

            MintlayerNodeGUI::IntializationError(e) => {
                let error_box = column![
                    iced::widget::text("Mintlayer-core node initialization failed".to_string())
                        .size(32),
                    iced::widget::text(e.to_string()).size(20),
                    iced::widget::button(text("Close")).on_press(Message::ShuttingDownFinished)
                ]
                .align_items(iced::Alignment::Center)
                .spacing(5);

                container(error_box)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x()
                    .center_y()
                    .into()
            }
        }
    }

    fn theme(&self) -> Self::Theme {
        Theme::Dark
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::subscription::events().map(Message::EventOccurred)
    }
}
