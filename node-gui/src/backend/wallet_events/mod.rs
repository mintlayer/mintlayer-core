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

use tokio::sync::Notify;
use wallet::wallet_events::WalletEvents;
use wallet_types::{AccountWalletTxId, WalletTx};

pub struct GuiWalletEvents {
    wallet_notify: Arc<Notify>,
    updated: bool,
}

impl GuiWalletEvents {
    pub fn new(wallet_notify: Arc<Notify>) -> Self {
        GuiWalletEvents {
            wallet_notify,
            updated: false,
        }
    }

    fn notify(&mut self) {
        self.updated = true;
        self.wallet_notify.notify_one();
    }

    /// Returns `true` if the wallet DB has been updated
    pub fn is_set(&self) -> bool {
        self.updated
    }

    /// Marks wallet as clean
    pub fn reset(&mut self) {
        self.updated = false;
    }
}

impl WalletEvents for GuiWalletEvents {
    fn new_block(&mut self) {
        self.notify();
    }

    fn set_transaction(&mut self, _id: &AccountWalletTxId, _tx: &WalletTx) {
        self.notify();
    }

    fn del_transaction(&mut self, _id: &AccountWalletTxId) {
        self.notify();
    }
}
