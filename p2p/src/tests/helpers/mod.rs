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

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures::Future;
use tokio::{sync::mpsc::UnboundedSender, time};

use logging::log;
use p2p_test_utils::LONG_TIMEOUT;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};

use crate::{
    net::types::{PeerInfo, PeerRole},
    peer_manager::{self, dns_seed::DnsSeed},
};

pub mod test_node;
pub mod test_node_group;

pub use test_node::*;
pub use test_node_group::*;

pub async fn timeout<F>(future: F)
where
    F: Future,
{
    // TODO: in the case of timeout, a panic is likely to occur in an unrelated place,
    // e.g. "subsystem manager's handle hasn't been joined" is a common one. This can be
    // confusing, so we need a way to abort the test before some unrelated code decides to panic.
    time::timeout(LONG_TIMEOUT, future).await.unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerNotification {
    BanScoreAdjustment {
        address: SocketAddress,
        new_score: u32,
    },
    Ban {
        address: BannableAddress,
    },
    Heartbeat,
    ConnectionAccepted {
        address: SocketAddress,
    },
}

pub struct PeerManagerObserver {
    event_tx: UnboundedSender<PeerManagerNotification>,
}

impl PeerManagerObserver {
    pub fn new(event_tx: UnboundedSender<PeerManagerNotification>) -> Self {
        Self { event_tx }
    }

    fn send_notification(&self, notification: PeerManagerNotification) {
        let send_result = self.event_tx.send(notification.clone());

        if let Err(err) = send_result {
            log::warn!("Error sending peer manager notification {notification:?}: {err}");
        }
    }
}

impl peer_manager::Observer for PeerManagerObserver {
    fn on_peer_ban_score_adjustment(&mut self, address: SocketAddress, new_score: u32) {
        self.send_notification(PeerManagerNotification::BanScoreAdjustment { address, new_score });
    }

    fn on_peer_ban(&mut self, address: BannableAddress) {
        self.send_notification(PeerManagerNotification::Ban { address });
    }

    fn on_heartbeat(&mut self) {
        self.send_notification(PeerManagerNotification::Heartbeat);
    }

    fn on_connection_acccepted(&mut self, address: SocketAddress) {
        self.send_notification(PeerManagerNotification::ConnectionAccepted { address });
    }
}

#[derive(Debug)]
pub struct TestPeerInfo {
    pub info: PeerInfo,
    pub role: PeerRole,
}

#[derive(Debug)]
pub struct TestPeersInfo {
    pub info: BTreeMap<SocketAddress, TestPeerInfo>,
}

impl TestPeersInfo {
    pub fn from_peer_mgr_peer_contexts(
        contexts: &BTreeMap<PeerId, peer_manager::peer_context::PeerContext>,
    ) -> Self {
        let mut info = BTreeMap::new();

        for ctx in contexts.values() {
            info.insert(
                ctx.address,
                TestPeerInfo {
                    info: ctx.info.clone(),
                    role: ctx.peer_role,
                },
            );
        }

        Self { info }
    }

    pub fn count_peers_by_role(&self, role: PeerRole) -> usize {
        self.info.iter().filter(|(_, info)| info.role == role).count()
    }
}

pub struct TestDnsSeed {
    addresses: Arc<Mutex<Vec<SocketAddress>>>,
}

impl TestDnsSeed {
    pub fn new(addresses: Arc<Mutex<Vec<SocketAddress>>>) -> Self {
        Self { addresses }
    }
}

#[async_trait]
impl DnsSeed for TestDnsSeed {
    async fn obtain_addresses(&self) -> Vec<SocketAddress> {
        self.addresses.lock().unwrap().clone()
    }
}
