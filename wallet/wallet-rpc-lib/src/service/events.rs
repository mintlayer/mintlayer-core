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
use logging::log;
use tokio::sync::mpsc;
use wallet_types::{
    wallet_tx::{self, BlockData},
    AccountId,
};

/// Events that can be emitted.
#[derive(Eq, PartialEq, serde::Serialize, Debug, Clone)]
pub enum Event {
    /// New block has been processed
    NewBlock {},

    /// Wallet transaction state has been updated
    TxUpdated {
        account_id: AccountId,
        tx_id: Id<Transaction>,
        state: TxState,
    },

    /// Transaction is no longer being tracked by the wallet
    TxDropped {
        account_id: AccountId,
        tx_id: Id<Transaction>,
    },

    /// Added a reward from given block
    RewardAdded {
        account_id: AccountId,

        #[serde(flatten)]
        data: BlockData,
    },

    /// Reward for given block has been dropped (due to reorg)
    RewardDropped {
        account_id: AccountId,
        block_id: Id<GenBlock>,
    },
}

/// Transaction state
#[derive(Eq, PartialEq, serde::Serialize, serde::Deserialize, Debug, Clone)]
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

    fn set_transaction(&self, id: &wallet_types::AccountWalletTxId, tx: &wallet_types::WalletTx) {
        let account_id = id.account_id().clone();

        let event = match (id.item_id().clone(), tx) {
            (OutPointSourceId::Transaction(tx_id), wallet_types::WalletTx::Tx(tx_data)) => {
                debug_assert_eq!(tx_data.get_transaction().get_id(), tx_id);
                Event::TxUpdated {
                    account_id,
                    tx_id,
                    state: (*tx_data.state()).into(),
                }
            }
            (OutPointSourceId::BlockReward(blk_id), wallet_types::WalletTx::Block(data)) => {
                debug_assert_eq!(blk_id, *data.block_id());
                let data = data.clone();
                Event::RewardAdded { account_id, data }
            }
            (OutPointSourceId::Transaction(tx_id), wallet_types::WalletTx::Block(_)) => {
                log::error!("INCONSISTENCY: Given transaction id {tx_id} but block data");
                return;
            }
            (OutPointSourceId::BlockReward(block_id), wallet_types::WalletTx::Tx(_)) => {
                log::error!("INCONSISTENCY: Given block id {block_id} but transaction data");
                return;
            }
        };

        self.emit(event);
    }

    fn del_transaction(&self, id: &wallet_types::AccountWalletTxId) {
        let account_id = id.account_id().clone();

        let event = match *id.item_id() {
            OutPointSourceId::Transaction(tx_id) => Event::TxDropped { account_id, tx_id },
            OutPointSourceId::BlockReward(block_id) => Event::RewardDropped {
                account_id,
                block_id,
            },
        };

        self.emit(event);
    }
}
