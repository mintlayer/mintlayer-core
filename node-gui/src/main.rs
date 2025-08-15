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

use heck::ToUpperCamelCase as _;
use iced::{
    advanced::graphics::core::window,
    executor, font,
    widget::{column, row, text, tooltip, Text},
    Element, Length, Settings, Size, Subscription, Task, Theme,
};
use iced_aw::widgets::spinner::Spinner;
use tokio::sync::mpsc::UnboundedReceiver;

use common::chain::config::ChainType;
use main_window::{MainWindow, MainWindowMessage};
use node_gui_backend::{
    messages::{BackendEvent, BackendRequest},
    node_initialize, BackendControls, BackendSender, InitNetwork, NodeInitializationOutcome,
    WalletMode,
};

const COLD_WALLET_TOOLTIP_TEXT: &str =
    "Start the wallet in Cold mode without connecting to the network or any nodes. The Cold mode is made to run the wallet on an air-gapped machine without internet connection for storage of keys of high-value. For example, pool decommission keys.";
const HOT_WALLET_TOOLTIP_TEXT: &str = "Start the wallet in Hot mode and connect to the network.";

const MAIN_NETWORK_TOOLTIP: &str = "The 'Mainnet' is the main network that has coins with value.";
const TEST_NETWORK_TOOLTIP: &str = "The 'Testnet' is the network with coins that have no value, but is used for testing various applications before deploying them on Mainnet.";

// Note: these are the default values used by iced.
const INITIAL_MAIN_WINDOW_WIDTH: f32 = 1024.0;
const INITIAL_MAIN_WINDOW_HEIGHT: f32 = 768.0;

pub fn main() -> iced::Result {
    utils::rust_backtrace::enable();

    let initial_opts = node_lib::Options::from_args(std::env::args_os());

    iced::application(title, update, view)
        .executor::<executor::Default>()
        .subscription(subscription)
        .theme(theme)
        .window(window::Settings {
            size: Size::new(INITIAL_MAIN_WINDOW_WIDTH, INITIAL_MAIN_WINDOW_HEIGHT),
            exit_on_close_request: false,
            ..Default::default()
        })
        .settings(Settings {
            id: Some("mintlayer-gui".to_owned()),
            antialiasing: true,
            ..Settings::default()
        })
        .font(iced_fonts::REQUIRED_FONT_BYTES)
        .run_with(|| initialize(initial_opts))
}

enum GuiState {
    Initial {
        initial_options: node_lib::Options,
    },
    SelectNetwork {
        top_level_options: node_lib::TopLevelOptions,
    },
    SelectWalletMode {
        resolved_options: node_lib::OptionsWithResolvedCommand,
    },
    Loading {
        wallet_mode: WalletMode,
        chain_type: ChainType,
    },
    Loaded {
        backend_sender: BackendSender,
        main_window: MainWindow,
    },
    InitializationInterrupted(InitializationInterruptionReason),
}

impl From<InitializationFailure> for GuiState {
    fn from(value: InitializationFailure) -> Self {
        Self::InitializationInterrupted(InitializationInterruptionReason::Failure(value))
    }
}

enum InitializationInterruptionReason {
    Failure(InitializationFailure),
    DataDirCleanedUp,
}

struct InitializationFailure {
    message: String,
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
    Loaded(anyhow::Result<NodeInitializationOutcome>),
    FontLoaded(Result<(), font::Error>),
    EventOccurred(iced::Event),
    ShuttingDownFinished,
    MainWindowMessage(MainWindowMessage),
}

fn initialize(initial_options: node_lib::Options) -> (GuiState, Task<Message>) {
    (
        GuiState::Initial { initial_options },
        font::load(iced_fonts::BOOTSTRAP_FONT_BYTES).map(Message::FontLoaded),
    )
}

fn chain_type_to_string(chain_type: ChainType) -> String {
    chain_type.name().to_upper_camel_case()
}

fn title(state: &GuiState) -> String {
    let version = env!("CARGO_PKG_VERSION");
    match state {
        GuiState::Initial { .. } => "Mintlayer Node - Initializing...".into(),
        GuiState::SelectNetwork { .. } => "Mintlayer Node - Selecting network...".into(),
        GuiState::SelectWalletMode { resolved_options } => {
            format!(
                "Mintlayer Node - {} - Selecting mode...",
                chain_type_to_string(resolved_options.command.chain_type())
            )
        }
        GuiState::Loading {
            wallet_mode: _,
            chain_type,
        } => format!(
            "Mintlayer Node - {} - Loading...",
            chain_type_to_string(*chain_type)
        ),
        GuiState::Loaded {
            backend_sender: _,
            main_window,
        } => {
            format!(
                "Mintlayer Node - {} - v{version}",
                chain_type_to_string(*main_window.node_state().chain_config().chain_type())
            )
        }
        GuiState::InitializationInterrupted(reason) => match reason {
            InitializationInterruptionReason::Failure(_) => "Mintlayer initialization error".into(),
            InitializationInterruptionReason::DataDirCleanedUp => {
                "Mintlayer data directory cleaned up".into()
            }
        },
    }
}

fn update(state: &mut GuiState, message: Message) -> Task<Message> {
    match state {
        GuiState::Initial { initial_options } => match message {
            Message::FontLoaded(Ok(())) => {
                match &initial_options.command {
                    Some(command) => {
                        *state = GuiState::SelectWalletMode {
                            resolved_options: node_lib::OptionsWithResolvedCommand {
                                top_level: initial_options.top_level.clone(),
                                command: command.clone(),
                            },
                        };
                    }
                    None => {
                        *state = GuiState::SelectNetwork {
                            top_level_options: initial_options.top_level.clone(),
                        };
                    }
                }
                Task::none()
            }
            Message::FontLoaded(Err(_)) => {
                *state = InitializationFailure {
                    message: "Failed to load font".into(),
                }
                .into();
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
        GuiState::SelectNetwork { top_level_options } => match message {
            Message::InitNetwork(init) => {
                let opts = node_lib::OptionsWithResolvedCommand {
                    top_level: top_level_options.clone(),
                    command: match init {
                        InitNetwork::Mainnet => node_lib::Command::Mainnet(Default::default()),
                        InitNetwork::Testnet => node_lib::Command::Testnet(Default::default()),
                        InitNetwork::Regtest => node_lib::Command::Regtest(Default::default()),
                    },
                };
                *state = GuiState::SelectWalletMode {
                    resolved_options: opts,
                };
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
        GuiState::SelectWalletMode { resolved_options } => {
            match message {
                Message::InitWalletMode(mode) => {
                    let opts = resolved_options.clone();

                    *state = GuiState::Loading {
                        wallet_mode: mode,
                        chain_type: opts.command.chain_type(),
                    };

                    Task::perform(node_initialize(opts, mode), Message::Loaded)
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
        GuiState::Loading {
            wallet_mode,
            chain_type: _,
        } => match message {
            Message::InitNetwork(_)
            | Message::InitWalletMode(_)
            | Message::FromBackend(_, _, _) => unreachable!(),
            Message::Loaded(Ok(init_outcome)) => match init_outcome {
                NodeInitializationOutcome::BackendControls(backend_controls) => {
                    let BackendControls {
                        initialized_node,
                        backend_sender,
                        backend_receiver,
                        low_priority_backend_receiver,
                    } = backend_controls;
                    *state = GuiState::Loaded {
                        backend_sender,
                        main_window: MainWindow::new(initialized_node, *wallet_mode),
                    };

                    recv_backend_command(backend_receiver, low_priority_backend_receiver)
                }
                NodeInitializationOutcome::DataDirCleanedUp => {
                    *state = GuiState::InitializationInterrupted(
                        InitializationInterruptionReason::DataDirCleanedUp,
                    );
                    Task::none()
                }
            },
            Message::Loaded(Err(e)) => {
                *state = InitializationFailure {
                    // Note: we need to use the alternate selector in order to show both anyhow::Error's context
                    // and the original error message.
                    message: format!("{e:#}"),
                }
                .into();
                Task::none()
            }
            Message::FontLoaded(status) => {
                if status.is_err() {
                    *state = InitializationFailure {
                        message: "Failed to load font".into(),
                    }
                    .into();
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
        GuiState::Loaded {
            backend_sender,
            main_window,
        } => match message {
            Message::FromBackend(
                backend_receiver,
                low_priority_backend_receiver,
                backend_event,
            ) => Task::batch([
                main_window
                    .update(
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
                    *state = InitializationFailure {
                        message: "Failed to load font".into(),
                    }
                    .into();
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
                main_window.update(msg, backend_sender).map(Message::MainWindowMessage)
            }
        },
        GuiState::InitializationInterrupted { .. } => match message {
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

fn view(state: &GuiState) -> Element<Message> {
    match state {
        GuiState::Initial { .. } => {
            iced::widget::text("Loading fonts...".to_string()).size(32).into()
        }
        GuiState::SelectNetwork { .. } => {
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
                    .style(iced::widget::container::bordered_box),
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
                    .style(iced::widget::container::bordered_box),
                ],
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            let res: Element<InitNetwork> =
                iced::widget::container(error_box).center(Length::Fill).into();

            res.map(Message::InitNetwork)
        }

        GuiState::SelectWalletMode { .. } => {
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
                    .style(iced::widget::container::bordered_box),
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
                    .style(iced::widget::container::bordered_box),
                ],
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            let res: Element<WalletMode> =
                iced::widget::container(error_box).center(Length::Fill).into();

            res.map(Message::InitWalletMode)
        }

        GuiState::Loading { .. } => {
            iced::widget::container(Spinner::new().width(Length::Fill).height(Length::Fill)).into()
        }

        GuiState::Loaded {
            backend_sender: _,
            main_window,
        } => main_window.view().map(Message::MainWindowMessage),

        GuiState::InitializationInterrupted(reason) => {
            let header_font_size = 32;
            let text_font_size = 20;

            let error_box = match reason {
                InitializationInterruptionReason::Failure(InitializationFailure { message }) => {
                    column![
                        iced::widget::text("Mintlayer-core node initialization failed".to_string())
                            .size(header_font_size),
                        iced::widget::text(message.to_string()).size(text_font_size)
                    ]
                }
                InitializationInterruptionReason::DataDirCleanedUp => {
                    column![
                        iced::widget::text("Data directory is now clean").size(header_font_size),
                        iced::widget::text("Please restart the node without `--clean-data` flag")
                            .size(text_font_size)
                    ]
                }
            };
            let error_box = error_box
                .extend([iced::widget::button(text("Close")).on_press(()).into()])
                .align_x(iced::Alignment::Center)
                .spacing(5);

            let res: Element<()> = iced::widget::container(error_box).center(Length::Fill).into();

            res.map(|_| Message::ShuttingDownFinished)
        }
    }
}

fn theme(_state: &GuiState) -> Theme {
    Theme::Light
}

fn subscription(_state: &GuiState) -> Subscription<Message> {
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
