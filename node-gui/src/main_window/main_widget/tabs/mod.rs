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

use iced::{Command, Element};
use iced_aw::{TabLabel, Tabs};

use crate::{
    backend::{messages::WalletId, BackendSender},
    main_window::NodeState,
};

use self::{
    network::{NetworkMessage, NetworkTab},
    settings::{SettingsMessage, SettingsTab, TabBarPosition},
    summary::{SummaryMessage, SummaryTab},
    wallet::{WalletMessage, WalletTab},
};

pub mod network;
pub mod settings;
pub mod summary;
pub mod wallet;

#[derive(Debug, Clone)]
pub enum TabsMessage {
    TabSelected(usize),
    WalletAdded(WalletId),
    WalletRemoved(WalletId),
    Summary(SummaryMessage),
    Network(NetworkMessage),
    Settings(SettingsMessage),
    WalletMessage(WalletId, WalletMessage),
}

pub struct TabsWidget {
    active_tab: usize,
    summary_tab: SummaryTab,
    network_tab: NetworkTab,
    settings_tab: SettingsTab,
    wallets: Vec<WalletTab>,
}

impl TabsWidget {
    pub fn new() -> Self {
        TabsWidget {
            active_tab: 0,
            summary_tab: SummaryTab::new(),
            network_tab: NetworkTab::new(),
            settings_tab: SettingsTab::new(),
            wallets: Vec::new(),
        }
    }

    pub fn last_wallet_tab_index(&self) -> usize {
        2 + self.wallets.len()
    }

    pub fn view(&self, node_state: &NodeState) -> Element<TabsMessage> {
        let position = self.settings_tab.settings().tab_bar_position.unwrap_or_default();

        let mut tabs = Tabs::new(self.active_tab, TabsMessage::TabSelected)
            .push(
                self.summary_tab.tab_label(),
                self.summary_tab.view(node_state),
            )
            .push(
                self.network_tab.tab_label(),
                self.network_tab.view(node_state),
            )
            .push(
                self.settings_tab.tab_label(),
                self.settings_tab.view(node_state),
            );

        for wallet in self.wallets.iter() {
            tabs = tabs.push(wallet.tab_label(), wallet.view(node_state))
        }

        tabs.icon_font(iced_aw::ICON_FONT)
            .tab_bar_position(match position {
                TabBarPosition::Top => iced_aw::TabBarPosition::Top,
                TabBarPosition::Bottom => iced_aw::TabBarPosition::Bottom,
            })
            .into()
    }

    pub fn update(
        &mut self,
        msg: TabsMessage,
        backend_sender: &BackendSender,
    ) -> Command<TabsMessage> {
        match msg {
            TabsMessage::TabSelected(n) => {
                self.active_tab = n;
                Command::none()
            }
            TabsMessage::WalletAdded(waller_id) => {
                let wallet_tab = WalletTab::new(waller_id);
                self.wallets.push(wallet_tab);
                self.active_tab = self.last_wallet_tab_index();
                Command::none()
            }
            TabsMessage::WalletRemoved(wallet_id) => {
                self.wallets.retain(|wallet_tab| wallet_tab.wallet_id() != wallet_id);
                if self.active_tab > self.last_wallet_tab_index() {
                    self.active_tab = self.last_wallet_tab_index();
                }
                Command::none()
            }
            TabsMessage::Summary(message) => {
                self.summary_tab.update(message).map(TabsMessage::Summary)
            }
            TabsMessage::Network(message) => {
                self.network_tab.update(message).map(TabsMessage::Network)
            }
            TabsMessage::Settings(message) => {
                self.settings_tab.update(message).map(TabsMessage::Settings)
            }
            TabsMessage::WalletMessage(wallet_id, message) => {
                if let Some(wallet_tab) =
                    self.wallets.iter_mut().find(|wallet_tab| wallet_tab.wallet_id() == wallet_id)
                {
                    wallet_tab
                        .update(message, backend_sender)
                        .map(move |msg| TabsMessage::WalletMessage(wallet_id, msg))
                } else {
                    Command::none()
                }
            }
        }
    }
}

trait Tab {
    type Message;

    fn title(&self) -> String;

    fn tab_label(&self) -> TabLabel;

    fn view(&self, node_state: &NodeState) -> Element<Self::Message> {
        self.content(node_state)
    }

    fn content(&self, node_state: &NodeState) -> Element<Self::Message>;
}
