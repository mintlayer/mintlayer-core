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

use common::chain::OutPointSourceId;
use crypto::key::hdkd::u31::U31;
use tokio::sync::mpsc::UnboundedSender;
use wallet::wallet_events::WalletEvents;
use wallet_types::WalletTx;

use super::messages::WalletId;

pub struct GuiWalletEvents {
    wallet_id: WalletId,
    wallet_updated_tx: UnboundedSender<WalletId>,
}

impl GuiWalletEvents {
    pub fn new(wallet_id: WalletId, wallet_updated_tx: UnboundedSender<WalletId>) -> Self {
        GuiWalletEvents {
            wallet_id,
            wallet_updated_tx,
        }
    }

    pub fn notify(&self) {
        let _ = self.wallet_updated_tx.send(self.wallet_id);
    }
}

impl WalletEvents for GuiWalletEvents {
    fn new_block(&self) {
        self.notify();
    }

    fn set_transaction(&self, _id: U31, _tx: &WalletTx) {
        self.notify();
    }

    fn del_transaction(&self, _id: U31, _source: OutPointSourceId) {
        self.notify();
    }
}
