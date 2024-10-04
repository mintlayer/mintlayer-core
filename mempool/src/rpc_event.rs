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
    chain::{Block, Transaction},
    primitives::{BlockHeight, Id},
};
use mempool_types::{tx_options::TxRelayPolicy, tx_origin::LocalTxOrigin};
use p2p_types::PeerId;

use crate::event::MempoolEvent;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc::description::HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcEvent {
    NewTip {
        id: Id<Block>,
        height: BlockHeight,
    },
    TransactionProcessed {
        tx_id: Id<Transaction>,
        origin: RpcTxOrigin,
        relay: RpcTxRelayPolicy,
        successful: bool,
    },
}

impl RpcEvent {
    pub fn from_event(event: MempoolEvent) -> Self {
        match event {
            MempoolEvent::NewTip(e) => RpcEvent::NewTip {
                id: *e.block_id(),
                height: e.block_height(),
            },
            MempoolEvent::TransactionProcessed(e) => RpcEvent::TransactionProcessed {
                tx_id: *e.tx_id(),
                origin: match e.origin() {
                    mempool_types::tx_origin::TxOrigin::Local(local_origin) => RpcTxOrigin::Local {
                        origin: match local_origin {
                            LocalTxOrigin::Mempool => RpcLocalTxOrigin::Mempool,
                            LocalTxOrigin::P2p => RpcLocalTxOrigin::P2p,
                            LocalTxOrigin::PastBlock => RpcLocalTxOrigin::PastBlock,
                        },
                    },
                    mempool_types::tx_origin::TxOrigin::Remote(r) => RpcTxOrigin::Remote {
                        peer_id: r.peer_id(),
                    },
                },
                relay: match e.relay_policy() {
                    TxRelayPolicy::DoRelay => RpcTxRelayPolicy::DoRelay,
                    TxRelayPolicy::DontRelay => RpcTxRelayPolicy::DontRelay,
                },
                successful: e.result().is_ok(),
            },
        }
    }
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcTxOrigin {
    Local { origin: RpcLocalTxOrigin },
    Remote { peer_id: PeerId },
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcLocalTxOrigin {
    Mempool,
    P2p,
    PastBlock,
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcTxRelayPolicy {
    DoRelay,
    DontRelay,
}
