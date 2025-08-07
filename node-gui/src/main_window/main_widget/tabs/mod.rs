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

use iced::{Element, Length, Task};
use iced_aw::{TabLabel, Tabs};
use strum::EnumCount;
use wallet_types::wallet_type::WalletType;

use node_gui_backend::{messages::WalletId, BackendSender};

use crate::{main_window::NodeState, WalletMode};

use self::{
    cold_wallet::ColdWalletTab,
    networking::{NetworkingMessage, NetworkingTab},
    settings::{SettingsMessage, SettingsTab, TabBarPosition},
    summary::{SummaryMessage, SummaryTab},
    wallet::{WalletMessage, WalletTab},
};

pub mod cold_wallet;
pub mod networking;
pub mod settings;
pub mod summary;
pub mod wallet;

#[derive(Debug, Clone)]
pub enum TabsMessage {
    TabSelected(usize),
    WalletAdded {
        wallet_id: WalletId,
        wallet_type: WalletType,
    },
    WalletRemoved(WalletId),
    Summary(SummaryMessage),
    Networking(NetworkingMessage),
    Settings(SettingsMessage),
    WalletMessage(WalletId, WalletMessage),
}

#[derive(EnumCount, Debug, Clone, Default)]
enum TabIndex {
    #[default]
    Summary = 0,
    Networking = 1,
    // TODO: enable setting when needed
    // Settings = 2,

    // Notice that the wallet tabs are added dynamically to these variants, so a higher index may be valid
}

impl TabIndex {
    fn into_usize(self) -> usize {
        self as usize
    }
}

pub struct TabsWidget {
    active_tab: usize,
    summary_tab: SummaryTab,
    networking_tab: NetworkingTab,
    settings_tab: SettingsTab,
    cold_wallet_tab: ColdWalletTab,
    wallets: Vec<WalletTab>,
    wallet_mode: WalletMode,
}

impl TabsWidget {
    pub fn new(wallet_mode: WalletMode) -> Self {
        TabsWidget {
            active_tab: TabIndex::default().into_usize(),
            summary_tab: SummaryTab::new(),
            networking_tab: NetworkingTab::new(),
            settings_tab: SettingsTab::new(),
            cold_wallet_tab: ColdWalletTab::new(),
            wallets: Vec::new(),
            wallet_mode,
        }
    }

    pub fn last_wallet_tab_index(&self) -> usize {
        TabIndex::COUNT + self.wallets.len() - 1
    }

    pub fn view(&self, node_state: &NodeState) -> Element<TabsMessage> {
        let position = self.settings_tab.settings().tab_bar_position.unwrap_or_default();

        let mut tabs = Tabs::new(TabsMessage::TabSelected).icon_font(iced_fonts::BOOTSTRAP_FONT);
        tabs = match self.wallet_mode {
            WalletMode::Hot => tabs
                .push(
                    TabIndex::Summary as usize,
                    self.summary_tab.tab_label(node_state),
                    self.summary_tab.content(node_state),
                )
                .push(
                    TabIndex::Networking as usize,
                    self.networking_tab.tab_label(node_state),
                    self.networking_tab.content(node_state),
                ),
            WalletMode::Cold => tabs.push(
                TabIndex::Summary as usize,
                self.cold_wallet_tab.tab_label(node_state),
                self.cold_wallet_tab.content(node_state),
            ),
        };
        // TODO: enable settings tab when needed
        //.push(
        //    TabIndex::Settings as usize,
        //    self.settings_tab.tab_label(node_state),
        //    self.settings_tab.content(node_state),
        //);

        for (idx, wallet) in self.wallets.iter().enumerate() {
            tabs = tabs.push(
                idx + TabIndex::COUNT,
                wallet.tab_label(node_state),
                wallet.content(node_state),
            )
        }

        tabs.tab_bar_position(match position {
            TabBarPosition::Top => iced_aw::TabBarPosition::Top,
            TabBarPosition::Bottom => iced_aw::TabBarPosition::Bottom,
        })
        .set_active_tab(&self.active_tab)
        .height(Length::Fill)
        .tab_bar_max_height(70.0)
        .into()
    }

    pub fn update(
        &mut self,
        msg: TabsMessage,
        backend_sender: &BackendSender,
    ) -> Task<TabsMessage> {
        match msg {
            TabsMessage::TabSelected(n) => {
                self.active_tab = n;
                Task::none()
            }
            TabsMessage::WalletAdded {
                wallet_id,
                wallet_type,
            } => {
                let wallet_tab = WalletTab::new(wallet_id, wallet_type);
                self.wallets.push(wallet_tab);
                self.active_tab = self.last_wallet_tab_index();
                Task::none()
            }
            TabsMessage::WalletRemoved(wallet_id) => {
                self.wallets.retain(|wallet_tab| wallet_tab.wallet_id() != wallet_id);
                if self.active_tab > self.last_wallet_tab_index() {
                    self.active_tab = self.last_wallet_tab_index();
                }
                Task::none()
            }
            TabsMessage::Summary(message) => {
                self.summary_tab.update(message).map(TabsMessage::Summary)
            }
            TabsMessage::Networking(message) => {
                self.networking_tab.update(message).map(TabsMessage::Networking)
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
                    Task::none()
                }
            }
        }
    }
}

trait Tab {
    type Message;

    fn tab_label(&self, node_state: &NodeState) -> TabLabel;

    fn content(&self, node_state: &NodeState) -> Element<Self::Message>;
}
