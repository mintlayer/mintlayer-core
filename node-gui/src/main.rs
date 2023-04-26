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
    MintlayerSplash::run(Settings {
        antialiasing: true,
        exit_on_close_request: false,
        try_opengles_first: true,
        ..Settings::default()
    })
}

#[derive(Debug)]

enum MintlayerSplash {
    Loading,
    Loaded(NodeController),
}

#[derive(Debug)]
enum Message {
    Loaded(anyhow::Result<NodeController>),
    EventOccurred(iced_native::Event),
    ShuttingDownFinished,
}

pub async fn initialize(
    remote_controller_sender: oneshot::Sender<RemoteController>,
) -> anyhow::Result<subsystem::Manager> {
    let opts = node_lib::Options::from_args(std::env::args_os());
    logging::init_logging::<&std::path::Path>(None);
    logging::log::info!("Command line options: {opts:?}");

    node_lib::run(opts, Some(remote_controller_sender)).await
}

fn do_shutdown(initialized_data: &mut NodeController) -> Command<Message> {
    if initialized_data.manager_join_handle.is_none() {
        return Command::none();
    }
    logging::log::error!("Starting shutdown process");
    let shutdown_trigger = initialized_data.shutdown_trigger.clone();
    let mut join_handle = None;
    std::mem::swap(&mut initialized_data.manager_join_handle, &mut join_handle);

    Command::perform(
        async move {
            shutdown_trigger.initiate();
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

        let manager =
            initialize(remote_controller_sender).await.expect("Node initialization failed");
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

impl Application for MintlayerSplash {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            MintlayerSplash::Loading,
            Command::perform(NodeController::load(), Message::Loaded),
        )
    }

    fn title(&self) -> String {
        match self {
            MintlayerSplash::Loading => ("Mintlayer Node - Loading...").to_string(),
            MintlayerSplash::Loaded(d) => {
                format!("Mintlayer Node - {}", d.chain_config.chain_type().name())
            }
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match self {
            MintlayerSplash::Loading => match message {
                Message::Loaded(Ok(initialized_data)) => {
                    *self = MintlayerSplash::Loaded(initialized_data);
                    Command::none()
                }
                // While the screen is loading, ignore all events
                Message::Loaded(Err(e)) => panic!("Error: {e}"),
                Message::EventOccurred(event) => {
                    if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                        panic!("Attempted shutdown during initialization")
                    } else {
                        Command::none()
                    }
                }
                Message::ShuttingDownFinished => Command::none(),
            },
            MintlayerSplash::Loaded(ref mut initialized_data) => {
                match message {
                    Message::Loaded(_) => Command::none(), // TODO: make this unreachable
                    // TODO: handle error on initialization
                    Message::EventOccurred(event) => {
                        if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                            do_shutdown(initialized_data)
                        } else {
                            Command::none()
                        }
                    }
                    Message::ShuttingDownFinished => iced::window::close(),
                }
            }
        }
    }

    fn view(&self) -> Element<Message> {
        match self {
            MintlayerSplash::Loading => {
                container(CupertinoSpinner::new().width(Length::Fill).height(Length::Fill)).into()
            }

            MintlayerSplash::Loaded(state) => {
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
