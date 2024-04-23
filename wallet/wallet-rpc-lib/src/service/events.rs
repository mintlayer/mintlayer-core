// Copyright (c) 2024 RBB S.r.l
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

use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock, OutPointSourceId, Transaction},
    primitives::{BlockHeight, Id, Idable},
};
use crypto::key::hdkd::u31::U31;
use logging::log;
use tokio::sync::mpsc;
use wallet_types::wallet_tx::{self, BlockData};

/// Events that can be emitted.
#[derive(Eq, PartialEq, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum Event {
    /// New block has been processed
    NewBlock {},

    /// Wallet transaction state has been updated
    TxUpdated {
        account_idx: u32,
        tx_id: Id<Transaction>,
        state: TxState,
    },

    /// Transaction is no longer being tracked by the wallet
    TxDropped {
        account_idx: u32,
        tx_id: Id<Transaction>,
    },

    /// Added a reward from given block
    RewardAdded {
        account_idx: u32,

        #[serde(flatten)]
        data: BlockData,
    },

    /// Reward for given block has been dropped (due to reorg)
    RewardDropped {
        account_idx: u32,
        block_id: Id<GenBlock>,
    },
}

/// Transaction state
#[derive(
    Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum TxState {
    /// Transaction was confirmed at given block height
    Confirmed {
        block_height: BlockHeight,
        block_timestamp: BlockTimestamp,
    },

    /// Transaction is in mempool
    InMempool {},

    /// Transaction conflicts with something in given confirmed block
    Conflicted { with_block: Id<GenBlock> },

    /// Transaction is inactive (not confirmed and not in mempool)
    Inactive {},

    /// Transaction abandoned by the user (implies [Self::Inactive])
    Abandoned {},
}

impl From<wallet_tx::TxState> for TxState {
    fn from(value: wallet_tx::TxState) -> Self {
        match value {
            wallet_tx::TxState::Confirmed(block_height, block_timestamp, _) => Self::Confirmed {
                block_height,
                block_timestamp,
            },
            wallet_tx::TxState::InMempool(_) => Self::InMempool {},
            wallet_tx::TxState::Conflicted(with_block) => Self::Conflicted { with_block },
            wallet_tx::TxState::Inactive(_) => Self::Inactive {},
            wallet_tx::TxState::Abandoned => Self::Abandoned {},
        }
    }
}

#[derive(Clone)]
pub struct WalletServiceEvents {
    sender: mpsc::UnboundedSender<Event>,
}

impl WalletServiceEvents {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Event>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    fn emit(&self, event: Event) {
        log::trace!("Emitting event {event:?}");
        if let Err(err) = self.sender.send(event) {
            log::warn!("Events channel closed unexpectedly: {err}");
        }
    }
}

impl wallet::wallet_events::WalletEvents for WalletServiceEvents {
    fn new_block(&self) {
        self.emit(Event::NewBlock {})
    }

    fn set_transaction(&self, account_idx: U31, tx: &wallet_types::WalletTx) {
        let account_idx = account_idx.into_u32();
        let event = match tx {
            wallet_types::WalletTx::Tx(tx_data) => {
                let tx_id = tx_data.get_transaction().get_id();
                Event::TxUpdated {
                    account_idx,
                    tx_id,
                    state: (*tx_data.state()).into(),
                }
            }
            wallet_types::WalletTx::Block(data) => {
                let data = data.clone();
                Event::RewardAdded { account_idx, data }
            }
        };

        self.emit(event);
    }

    fn del_transaction(&self, id: U31, source: OutPointSourceId) {
        let account_idx = id.into_u32();

        let event = match source {
            OutPointSourceId::Transaction(tx_id) => Event::TxDropped { account_idx, tx_id },
            OutPointSourceId::BlockReward(block_id) => Event::RewardDropped {
                account_idx,
                block_id,
            },
        };

        self.emit(event);
    }
}
