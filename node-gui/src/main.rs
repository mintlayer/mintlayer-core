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

use std::fmt::Debug;
use std::sync::Arc;

use common::chain::ChainConfig;
use iced::widget::{column, container, text};
use iced::{alignment, Subscription};
use iced::{executor, Application, Command, Element, Length, Settings, Theme};
use iced_aw::native::cupertino::cupertino_spinner::CupertinoSpinner;
use node_lib::remote_controller::RemoteController;
use subsystem::manager::ShutdownTrigger;
use tokio::sync::oneshot;

pub fn main() -> iced::Result {
    MintlayerNodeGUI::run(Settings {
        antialiasing: true,
        exit_on_close_request: false,
        try_opengles_first: true,
        ..Settings::default()
    })
}

#[derive(Debug)]

enum MintlayerNodeGUI {
    Loading,
    Loaded(NodeController),
}

#[derive(Debug)]
enum Message {
    Loaded(anyhow::Result<NodeController>),
    EventOccurred(iced_native::Event),
    ShuttingDownFinished,
}

fn do_shutdown(controller: &mut NodeController) -> Command<Message> {
    // We shutdown and join only once, so this being None means we took the handle already
    if controller.manager_join_handle.is_none() {
        logging::log::error!("Shutdown already requested.");
        return Command::none();
    }
    logging::log::error!("Starting shutdown process...");

    controller.shutdown_trigger.initiate();

    let mut join_handle = None;
    std::mem::swap(&mut controller.manager_join_handle, &mut join_handle);

    Command::perform(
        async move {
            join_handle.expect("Must be found").await.expect("Joining failed");
        },
        |_| Message::ShuttingDownFinished,
    )
}

struct NodeController {
    chain_config: Arc<ChainConfig>,
    _controller: RemoteController,
    shutdown_trigger: ShutdownTrigger,
    manager_join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Debug for NodeController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeInitializationData")
            .field("chain_config", &self.chain_config)
            .finish()
    }
}

impl NodeController {
    async fn load() -> anyhow::Result<NodeController> {
        let (remote_controller_sender, remote_controller_receiver) = oneshot::channel();

        let opts = node_lib::Options::from_args(std::env::args_os());
        logging::init_logging::<&std::path::Path>(None);
        logging::log::info!("Command line options: {opts:?}");

        let manager = node_lib::run(opts, Some(remote_controller_sender)).await?;
        let shutdown_trigger = manager.make_shutdown_trigger();

        let controller =
            remote_controller_receiver.await.expect("Node controller receiving failed");

        let manager_join_handle = tokio::spawn(async move { manager.main().await });

        let chain_config = controller
            .chainstate
            .call(|this| this.get_chain_config().clone())
            .await
            .expect("Chain config retrieval failed after node initialization");

        let node_controller = NodeController {
            chain_config,
            _controller: controller,
            shutdown_trigger,
            manager_join_handle: Some(manager_join_handle),
        };

        Ok(node_controller)
    }
}

impl Application for MintlayerNodeGUI {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            MintlayerNodeGUI::Loading,
            Command::perform(NodeController::load(), Message::Loaded),
        )
    }

    fn title(&self) -> String {
        match self {
            MintlayerNodeGUI::Loading => ("Mintlayer Node - Loading...").to_string(),
            MintlayerNodeGUI::Loaded(d) => {
                format!("Mintlayer Node - {}", d.chain_config.chain_type().name())
            }
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match self {
            MintlayerNodeGUI::Loading => match message {
                Message::Loaded(Ok(controller)) => {
                    *self = MintlayerNodeGUI::Loaded(controller);
                    Command::none()
                }
                // TODO: handle error on initialization
                Message::Loaded(Err(e)) => panic!("Error: {e}"),
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        panic!("Attempted shutdown during initialization")
                    } else {
                        // While the screen is loading, ignore all events
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => Command::none(),
            },
            MintlayerNodeGUI::Loaded(ref mut controller) => match message {
                Message::Loaded(_) => unreachable!("Already loaded"),
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        do_shutdown(controller)
                    } else {
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => iced::window::close(),
            },
        }
    }

    fn view(&self) -> Element<Message> {
        match self {
            MintlayerNodeGUI::Loading => {
                container(CupertinoSpinner::new().width(Length::Fill).height(Length::Fill)).into()
            }

            MintlayerNodeGUI::Loaded(state) => {
                let main_widget = text(&format!(
                    "Genesis block: {}",
                    state.chain_config.genesis_block_id(),
                ))
                .width(Length::Fill)
                .size(25)
                .horizontal_alignment(alignment::Horizontal::Center)
                .vertical_alignment(alignment::Vertical::Center);

                let window_contents = column![main_widget];

                container(window_contents)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_y()
                    .into()
            }
        }
    }

    fn theme(&self) -> Self::Theme {
        Theme::Light
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::subscription::events().map(Message::EventOccurred)
    }
}
