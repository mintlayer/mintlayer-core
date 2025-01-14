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

#![windows_subsystem = "windows"]

mod main_window;
mod widgets;

use std::convert::identity;
use std::env;

use common::time_getter::TimeGetter;
use iced::advanced::graphics::core::window;
use iced::widget::{column, container, row, text, tooltip, Text};
use iced::{executor, Element, Length, Settings, Task, Theme};
use iced::{font, Subscription};
use iced_aw::widgets::spinner::Spinner;
use main_window::{MainWindow, MainWindowMessage};
use node_gui_backend::{
    messages::{BackendEvent, BackendRequest},
    node_initialize, BackendControls, BackendSender, InitNetwork, WalletMode,
};
use tokio::sync::mpsc::UnboundedReceiver;

const COLD_WALLET_TOOLTIP_TEXT: &str =
    "Start the wallet in Cold mode without connecting to the network or any nodes. The Cold mode is made to run the wallet on an air-gapped machine without internet connection for storage of keys of high-value. For example, pool decommission keys.";
const HOT_WALLET_TOOLTIP_TEXT: &str = "Start the wallet in Hot mode and connect to the network.";

const MAIN_NETWORK_TOOLTIP: &str = "The 'Mainnet' is the main network that has coins with value.";
const TEST_NETWORK_TOOLTIP: &str = "The 'Testnet' is the network with coins that have no value, but is used for testing various applications before deploying them on Mainnet.";

pub fn main() -> iced::Result {
    utils::rust_backtrace::enable();

    iced::application(title, update, view)
        .executor::<executor::Default>()
        .subscription(subscription)
        .theme(theme)
        .window(window::Settings {
            exit_on_close_request: false,
            ..Default::default()
        })
        .settings(Settings {
            id: Some("mintlayer-gui".to_owned()),
            antialiasing: true,
            ..Settings::default()
        })
        .run_with(initialize)
}

enum MintlayerNodeGUI {
    Initial,
    SelectNetwork,
    SelectWalletMode(InitNetwork),
    Loading(WalletMode),
    Loaded(BackendSender, MainWindow),
    IntializationError(String),
}

#[derive(Debug)]
pub enum Message {
    InitNetwork(InitNetwork),
    InitWalletMode(WalletMode),
    FromBackend(
        UnboundedReceiver<BackendEvent>,
        UnboundedReceiver<BackendEvent>,
        BackendEvent,
    ),
    Loaded(anyhow::Result<BackendControls>),
    FontLoaded(Result<(), font::Error>),
    EventOccurred(iced::Event),
    ShuttingDownFinished,
    MainWindowMessage(MainWindowMessage),
}

fn initialize() -> (MintlayerNodeGUI, Task<Message>) {
    (
        MintlayerNodeGUI::Initial,
        font::load(iced_fonts::BOOTSTRAP_FONT_BYTES).map(Message::FontLoaded),
    )
}

fn title(state: &MintlayerNodeGUI) -> String {
    let version = env!("CARGO_PKG_VERSION");
    match state {
        MintlayerNodeGUI::Initial => "Mintlayer Node - Initializing...".to_string(),
        MintlayerNodeGUI::SelectNetwork => "Mintlayer Node - Selecting network...".to_string(),
        MintlayerNodeGUI::SelectWalletMode(_) => "Mintlayer Node - Selecting mode...".to_string(),
        MintlayerNodeGUI::Loading(_) => "Mintlayer Node - Loading...".to_string(),
        MintlayerNodeGUI::Loaded(_backend_sender, w) => {
            format!(
                "Mintlayer Node - {} - v{version}",
                w.node_state().chain_config().chain_type().name()
            )
        }
        MintlayerNodeGUI::IntializationError(_) => "Mintlayer initialization error".to_string(),
    }
}

fn update(state: &mut MintlayerNodeGUI, message: Message) -> Task<Message> {
    match state {
        MintlayerNodeGUI::Initial => match message {
            Message::FontLoaded(Ok(())) => {
                *state = MintlayerNodeGUI::SelectNetwork;
                Task::none()
            }
            Message::FontLoaded(Err(_)) => {
                *state = MintlayerNodeGUI::IntializationError("Failed to load font".into());
                Task::none()
            }
            Message::ShuttingDownFinished => {
                iced::window::get_latest().and_then(iced::window::close)
            }
            Message::EventOccurred(event) => {
                if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                    iced::window::get_latest().and_then(iced::window::close)
                } else {
                    // While the screen is loading, ignore all events
                    Task::none()
                }
            }
            Message::Loaded(_)
            | Message::InitNetwork(_)
            | Message::InitWalletMode(_)
            | Message::FromBackend(_, _, _)
            | Message::MainWindowMessage(_) => unreachable!(),
        },
        MintlayerNodeGUI::SelectNetwork => match message {
            Message::InitNetwork(init) => {
                *state = MintlayerNodeGUI::SelectWalletMode(init);
                Task::none()
            }
            Message::ShuttingDownFinished => {
                iced::window::get_latest().and_then(iced::window::close)
            }
            Message::EventOccurred(event) => {
                if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                    iced::window::get_latest().and_then(iced::window::close)
                } else {
                    // While the screen is loading, ignore all events
                    Task::none()
                }
            }
            Message::Loaded(_)
            | Message::InitWalletMode(_)
            | Message::FontLoaded(_)
            | Message::FromBackend(_, _, _)
            | Message::MainWindowMessage(_) => unreachable!(),
        },
        MintlayerNodeGUI::SelectWalletMode(init) => {
            let init = *init;
            match message {
                Message::InitWalletMode(mode) => {
                    *state = MintlayerNodeGUI::Loading(mode);

                    Task::perform(
                        node_initialize(TimeGetter::default(), init, mode),
                        Message::Loaded,
                    )
                }
                Message::ShuttingDownFinished => {
                    iced::window::get_latest().and_then(iced::window::close)
                }
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        iced::window::get_latest().and_then(iced::window::close)
                    } else {
                        // While the screen is loading, ignore all events
                        Task::none()
                    }
                }
                Message::InitNetwork(_)
                | Message::Loaded(_)
                | Message::FontLoaded(_)
                | Message::FromBackend(_, _, _)
                | Message::MainWindowMessage(_) => unreachable!(),
            }
        }
        MintlayerNodeGUI::Loading(mode) => match message {
            Message::InitNetwork(_)
            | Message::InitWalletMode(_)
            | Message::FromBackend(_, _, _) => unreachable!(),
            Message::Loaded(Ok(backend_controls)) => {
                let BackendControls {
                    initialized_node,
                    backend_sender,
                    backend_receiver,
                    low_priority_backend_receiver,
                } = backend_controls;
                *state = MintlayerNodeGUI::Loaded(
                    backend_sender,
                    MainWindow::new(initialized_node, *mode),
                );
                recv_backend_command(backend_receiver, low_priority_backend_receiver)
            }
            Message::Loaded(Err(e)) => {
                *state = MintlayerNodeGUI::IntializationError(e.to_string());
                Task::none()
            }
            Message::FontLoaded(status) => {
                if status.is_err() {
                    *state = MintlayerNodeGUI::IntializationError("Failed to load font".into());
                }
                Task::none()
            }
            Message::EventOccurred(event) => {
                if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                    panic!("Attempted shutdown during initialization")
                } else {
                    // While the screen is loading, ignore all events
                    Task::none()
                }
            }
            Message::ShuttingDownFinished => Task::none(),
            Message::MainWindowMessage(_) => Task::none(),
        },
        MintlayerNodeGUI::Loaded(backend_sender, w) => match message {
            Message::FromBackend(
                backend_receiver,
                low_priority_backend_receiver,
                backend_event,
            ) => Task::batch([
                w.update(
                    MainWindowMessage::FromBackend(backend_event),
                    backend_sender,
                )
                .map(Message::MainWindowMessage),
                recv_backend_command(backend_receiver, low_priority_backend_receiver),
            ]),
            Message::InitNetwork(_) | Message::InitWalletMode(_) | Message::Loaded(_) => {
                unreachable!("Already loaded")
            }
            Message::FontLoaded(status) => {
                if status.is_err() {
                    *state = MintlayerNodeGUI::IntializationError("Failed to load font".into());
                }
                Task::none()
            }
            Message::EventOccurred(event) => {
                if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                    // TODO: this event doesn't cover the case of closing the Window through Cmd+Q in MacOS
                    backend_sender.send(BackendRequest::Shutdown);
                    Task::none()
                } else {
                    Task::none()
                }
            }
            Message::ShuttingDownFinished => {
                iced::window::get_latest().and_then(iced::window::close)
            }
            Message::MainWindowMessage(msg) => {
                w.update(msg, backend_sender).map(Message::MainWindowMessage)
            }
        },
        MintlayerNodeGUI::IntializationError(_) => match message {
            Message::InitNetwork(_)
            | Message::InitWalletMode(_)
            | Message::FromBackend(_, _, _) => unreachable!(),
            Message::Loaded(_) => Task::none(),
            Message::FontLoaded(_) => Task::none(),
            Message::EventOccurred(event) => {
                if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                    iced::window::get_latest().and_then(iced::window::close)
                } else {
                    Task::none()
                }
            }
            Message::ShuttingDownFinished => {
                iced::window::get_latest().and_then(iced::window::close)
            }
            Message::MainWindowMessage(_) => Task::none(),
        },
    }
}

fn view(state: &MintlayerNodeGUI) -> Element<Message> {
    match state {
        MintlayerNodeGUI::Initial => {
            iced::widget::text("Loading fonts...".to_string()).size(32).into()
        }
        MintlayerNodeGUI::SelectNetwork => {
            let error_box = column![
                iced::widget::text("Please choose the network you want to use".to_string())
                    .size(32),
                row![
                    iced::widget::button(text("Mainnet")).on_press(InitNetwork::Mainnet),
                    tooltip(
                        Text::new(iced_fonts::Bootstrap::Question.to_string())
                            .font(iced_fonts::BOOTSTRAP_FONT),
                        MAIN_NETWORK_TOOLTIP,
                        tooltip::Position::Bottom
                    )
                    .gap(10)
                ],
                row![
                    iced::widget::button(text("Testnet")).on_press(InitNetwork::Testnet),
                    tooltip(
                        Text::new(iced_fonts::Bootstrap::Question.to_string())
                            .font(iced_fonts::BOOTSTRAP_FONT),
                        TEST_NETWORK_TOOLTIP,
                        tooltip::Position::Bottom
                    )
                    .gap(10)
                ],
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            let res: Element<InitNetwork> =
                container(error_box).center_x(Length::Fill).center_y(Length::Fill).into();

            res.map(Message::InitNetwork)
        }

        MintlayerNodeGUI::SelectWalletMode(_) => {
            let error_box = column![
                iced::widget::text("Please choose the wallet mode".to_string()).size(32),
                row![
                    iced::widget::button(text("Hot")).on_press(WalletMode::Hot),
                    tooltip(
                        Text::new(iced_fonts::Bootstrap::Question.to_string())
                            .font(iced_fonts::BOOTSTRAP_FONT),
                        HOT_WALLET_TOOLTIP_TEXT,
                        tooltip::Position::Bottom
                    )
                    .gap(10)
                ],
                row![
                    iced::widget::button(text("Cold")).on_press(WalletMode::Cold),
                    tooltip(
                        Text::new(iced_fonts::Bootstrap::Question.to_string())
                            .font(iced_fonts::BOOTSTRAP_FONT),
                        COLD_WALLET_TOOLTIP_TEXT,
                        tooltip::Position::Bottom
                    )
                    .gap(10)
                ],
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            let res: Element<WalletMode> =
                container(error_box).center_x(Length::Fill).center_y(Length::Fill).into();

            res.map(Message::InitWalletMode)
        }

        MintlayerNodeGUI::Loading(_) => {
            container(Spinner::new().width(Length::Fill).height(Length::Fill)).into()
        }

        MintlayerNodeGUI::Loaded(_backend_sender, w) => w.view().map(Message::MainWindowMessage),

        MintlayerNodeGUI::IntializationError(e) => {
            let error_box = column![
                iced::widget::text("Mintlayer-core node initialization failed".to_string())
                    .size(32),
                iced::widget::text(e.to_string()).size(20),
                iced::widget::button(text("Close")).on_press(())
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            let res: Element<()> =
                container(error_box).center_x(Length::Fill).center_y(Length::Fill).into();

            res.map(|_| Message::ShuttingDownFinished)
        }
    }
}

fn theme(_state: &MintlayerNodeGUI) -> Theme {
    Theme::Light
}

fn subscription(_state: &MintlayerNodeGUI) -> Subscription<Message> {
    iced::event::listen().map(Message::EventOccurred)
}

fn recv_backend_command(
    mut backend_receiver: UnboundedReceiver<BackendEvent>,
    mut low_priority_backend_receiver: UnboundedReceiver<BackendEvent>,
) -> Task<Message> {
    Task::perform(
        async move {
            tokio::select! {
                // Make sure we process low priority events at the end
                biased;

                msg_opt = backend_receiver.recv() => {
                    match msg_opt {
                        Some(msg) => Message::FromBackend(backend_receiver, low_priority_backend_receiver, msg),
                        None => Message::ShuttingDownFinished,
                    }
                }
                msg_opt = low_priority_backend_receiver.recv() => {
                    match msg_opt {
                        Some(msg) => Message::FromBackend(backend_receiver, low_priority_backend_receiver, msg),
                        None => Message::ShuttingDownFinished,
                    }
                }
            }
        },
        identity,
    )
}
