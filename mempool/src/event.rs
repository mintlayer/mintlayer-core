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

use common::{
    chain::{Block, Transaction},
    primitives::{BlockHeight, Id},
};
use utils::ensure;

use crate::{
    error::{Error, MempoolBanScore},
    tx_options::TxRelayPolicy,
    tx_origin::TxOrigin,
};

/// Event triggered when a transaction has been fully validated
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TransactionProcessed {
    tx_id: Id<Transaction>,
    origin: TxOrigin,
    relay_policy: TxRelayPolicy,
    result: crate::Result<()>,
}

impl TransactionProcessed {
    fn new(
        tx_id: Id<Transaction>,
        origin: TxOrigin,
        relay_policy: TxRelayPolicy,
        result: crate::Result<()>,
    ) -> Self {
        Self {
            tx_id,
            origin,
            relay_policy,
            result,
        }
    }

    pub fn accepted(tx_id: Id<Transaction>, relay_policy: TxRelayPolicy, origin: TxOrigin) -> Self {
        Self::new(tx_id, origin, relay_policy, Ok(()))
    }

    pub fn rejected(tx_id: Id<Transaction>, err: Error, origin: TxOrigin) -> Self {
        Self::new(tx_id, origin, TxRelayPolicy::DontRelay, Err(err))
    }

    pub fn result(&self) -> &crate::Result<()> {
        &self.result
    }

    pub fn was_accepted(&self) -> bool {
        self.result.is_ok()
    }

    pub fn ban_score(&self) -> u32 {
        self.result.as_ref().map_or_else(|err| err.mempool_ban_score(), |_| 0)
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        &self.tx_id
    }

    pub fn origin(&self) -> TxOrigin {
        self.origin
    }

    pub fn relay_policy(&self) -> TxRelayPolicy {
        self.relay_policy
    }

    pub fn to_rpc_event(&self) -> Option<RpcMempoolEvent> {
        let Self {
            tx_id,
            origin,
            relay_policy: _,
            result,
        } = self;

        // Only emit events for transactions that actually end up in mempool
        ensure!(result.is_ok());

        Some(RpcMempoolEvent::TxProcessed {
            tx_id: *tx_id,
            origin: *origin,
        })
    }
}

/// Event triggered when mempool has synced up to given tip
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NewTip {
    block_id: Id<Block>,
    height: BlockHeight,
}

impl NewTip {
    pub fn new(block_id: Id<Block>, height: BlockHeight) -> Self {
        Self { block_id, height }
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn block_height(&self) -> BlockHeight {
        self.height
    }
}

/// Events emitted by mempool destined for other subsystems
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MempoolEvent {
    NewTip(NewTip),
    TransactionProcessed(TransactionProcessed),
}

impl MempoolEvent {
    pub fn to_rpc_event(&self) -> Option<RpcMempoolEvent> {
        match self {
            MempoolEvent::NewTip(new_tip) => Some(RpcMempoolEvent::NewTip(new_tip.clone())),
            MempoolEvent::TransactionProcessed(tx_processed) => tx_processed.to_rpc_event(),
        }
    }
}

impl From<TransactionProcessed> for MempoolEvent {
    fn from(event: TransactionProcessed) -> Self {
        Self::TransactionProcessed(event)
    }
}

impl From<NewTip> for MempoolEvent {
    fn from(event: NewTip) -> Self {
        Self::NewTip(event)
    }
}

/// Events emitted by mempool destined for RPC subscribers
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RpcMempoolEvent {
    NewTip(NewTip),

    TxProcessed {
        tx_id: Id<Transaction>,
        origin: TxOrigin,
    },

    TxEvicted {
        tx_id: Id<Transaction>,
        origin: TxOrigin,
    },
}

impl RpcMempoolEvent {
    pub fn tx_processed(tx_id: Id<Transaction>, origin: TxOrigin) -> Self {
        Self::TxProcessed { tx_id, origin }
    }

    pub fn tx_evicted(tx_id: Id<Transaction>, origin: TxOrigin) -> Self {
        Self::TxEvicted { tx_id, origin }
    }
}

impl From<NewTip> for RpcMempoolEvent {
    fn from(new_tip: NewTip) -> Self {
        Self::NewTip(new_tip)
    }
}
