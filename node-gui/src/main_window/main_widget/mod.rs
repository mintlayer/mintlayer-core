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

pub mod tabs;

use iced::{Element, Task};
use node_gui_backend::{messages::WalletId, BackendSender};
use wallet_types::wallet_type::WalletType;

use crate::WalletMode;

use super::NodeState;

#[derive(Debug, Clone)]
pub enum MainWidgetMessage {
    WalletAdded {
        wallet_id: WalletId,
        wallet_type: WalletType,
    },
    WalletRemoved(WalletId),
    TabsMessage(tabs::TabsMessage),
}

pub struct MainWidget {
    tabs: tabs::TabsWidget,
}

impl MainWidget {
    pub fn new(wallet_mode: WalletMode) -> Self {
        Self {
            tabs: tabs::TabsWidget::new(wallet_mode),
        }
    }

    pub fn update(
        &mut self,
        msg: MainWidgetMessage,
        backend_sender: &BackendSender,
    ) -> Task<MainWidgetMessage> {
        match msg {
            MainWidgetMessage::WalletAdded {
                wallet_id,
                wallet_type,
            } => Task::perform(async {}, move |_| {
                MainWidgetMessage::TabsMessage(tabs::TabsMessage::WalletAdded {
                    wallet_id,
                    wallet_type,
                })
            }),
            MainWidgetMessage::WalletRemoved(wallet_id) => Task::perform(async {}, move |_| {
                MainWidgetMessage::TabsMessage(tabs::TabsMessage::WalletRemoved(wallet_id))
            }),
            MainWidgetMessage::TabsMessage(tabs_message) => self
                .tabs
                .update(tabs_message, backend_sender)
                .map(MainWidgetMessage::TabsMessage),
        }
    }

    pub fn view(&self, node_state: &NodeState) -> Element<'_, MainWidgetMessage> {
        self.tabs.view(node_state).map(MainWidgetMessage::TabsMessage)
    }
}
