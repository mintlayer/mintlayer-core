// Copyright (c) 2023 RBB S.r.l
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

use std::sync::Arc;

use common::chain::ChainConfig;
use iced::{
    alignment::{Horizontal, Vertical},
    widget::{Column, Container, Text},
    Application, Element, Font, Length, Settings, Theme,
};
use iced_aw::{TabLabel, Tabs};

mod dashboard;
use dashboard::{DashboardMessage, DashboardTab};

mod settings;
use logging::log;
use node_lib::remote_controller::RemoteController;
use settings::{SettingsMessage, SettingsTab, TabPosition};
use tokio::sync::oneshot;

const HEADER_SIZE: u16 = 32;
const TAB_PADDING: u16 = 16;

const ICON_FONT: Font = iced::Font::External {
    name: "Icons",
    bytes: include_bytes!("../fonts/icons.ttf"),
};

enum Icon {
    User,
    CogAlt,
}

impl From<Icon> for char {
    fn from(icon: Icon) -> Self {
        match icon {
            Icon::User => '\u{E800}',
            Icon::CogAlt => '\u{E802}',
        }
    }
}

pub async fn initialize(
    remote_controller_sender: oneshot::Sender<RemoteController>,
) -> anyhow::Result<subsystem::Manager> {
    let opts = node_lib::Options::from_args(std::env::args_os());
    logging::init_logging::<&std::path::Path>(None);
    logging::log::info!("Command line options: {opts:?}");

    node_lib::run(opts, Some(remote_controller_sender)).await
}

#[tokio::main]
async fn main() -> iced::Result {
    let (remote_controller_sender, remote_controller_receiver) = oneshot::channel();

    let manager = initialize(remote_controller_sender).await.expect("Node initialization failed");
    let shutdown_trigger = manager.make_shutdown_trigger();

    let controller = remote_controller_receiver.await.expect("Node controller receiving failed");

    let chain_config = controller
        .chainstate
        .call(|this| this.get_chain_config().clone())
        .await
        .expect("Chain config retrieval failed after node initialization");

    let node_controller = NodeInitializationData {
        chain_config,
        controller,
    };

    let manager_join_handle = tokio::spawn(async move { manager.main().await });

    let gui_settings = Settings {
        antialiasing: true,
        flags: Some(node_controller),
        ..Settings::default()
    };

    tokio::task::block_in_place(|| MintlayerGUI::run(gui_settings))?;

    shutdown_trigger.initiate();

    {
        let err = "Joining subsystem manager failed. Clean shutdown couldn't be performed.";
        manager_join_handle.await.expect(err);
    }

    Ok(())
}

struct MintlayerGUI {
    active_tab: usize,
    dashboard_tab: DashboardTab,
    settings_tab: SettingsTab,
}

struct NodeInitializationData {
    chain_config: Arc<ChainConfig>,
    controller: RemoteController,
}

#[derive(Clone, Debug)]
enum Message {
    TabSelected(usize),
    Dashboard(DashboardMessage),
    Settings(SettingsMessage),
}

#[derive(Debug, Clone)]
struct InitializationState {
    hello: String,
}

impl InitializationState {
    async fn load() -> Result<InitializationState, ()> {
        log::info!("Starting node...");
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        return Ok(Self {
            hello: "Loaded!".to_string(),
        });
    }
}

impl Application for MintlayerGUI {
    type Message = Message;
    type Executor = iced::executor::Default;
    type Theme = Theme;
    type Flags = Option<NodeInitializationData>;

    fn new(init_data: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        let gui = MintlayerGUI {
            active_tab: 0,
            dashboard_tab: DashboardTab::new(),
            settings_tab: SettingsTab::new(),
        };

        (
            gui,
            // TODO: put the initialization result here
            iced::Command::perform(
                InitializationState::load(),
                |_: Result<InitializationState, ()>| Message::TabSelected(0),
            ),
        )
    }

    fn title(&self) -> String {
        String::from("Mintlayer Node")
    }

    fn update(&mut self, message: Self::Message) -> iced::Command<Message> {
        match message {
            Message::TabSelected(selected) => self.active_tab = selected,
            Message::Dashboard(message) => self.dashboard_tab.update(message),
            Message::Settings(message) => self.settings_tab.update(message),
        }
        iced::Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let position = self.settings_tab.settings().tab_bar_position.unwrap_or_default();
        let theme = self.settings_tab.settings().tab_bar_theme.unwrap_or_default();

        Tabs::new(self.active_tab, Message::TabSelected)
            .push(self.dashboard_tab.tab_label(), self.dashboard_tab.view())
            .push(self.settings_tab.tab_label(), self.settings_tab.view())
            .tab_bar_style(theme)
            .icon_font(ICON_FONT)
            .tab_bar_position(match position {
                TabPosition::Top => iced_aw::TabBarPosition::Top,
                TabPosition::Bottom => iced_aw::TabBarPosition::Bottom,
            })
            .into()
    }
}

trait Tab {
    type Message;

    fn title(&self) -> String;

    fn tab_label(&self) -> TabLabel;

    fn view(&self) -> Element<'_, Self::Message> {
        let column = Column::new()
            .spacing(20)
            .push(Text::new(self.title()).size(HEADER_SIZE))
            .push(self.content());

        Container::new(column)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .padding(TAB_PADDING)
            .into()
    }

    fn content(&self) -> Element<'_, Self::Message>;
}
