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
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use p2p_test_utils::P2pBasicTestTimeGetter;
use tokio::sync::mpsc::UnboundedSender;

use logging::log;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};

use crate::{
    net::{
        default_backend::transport::TransportSocket,
        types::{PeerInfo, PeerRole},
    },
    peer_manager::{self, dns_seed::DnsSeed},
};

pub mod test_node;
pub mod test_node_group;

pub use test_node::*;
pub use test_node_group::*;

// TODO: test utilities related to peer manager should probably go into peer_manager/tests.
// Or perhaps we should have a dedicated test_helpers module, which wouldn't be specific to
// any particular kind of tests.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerNotification {
    BanScoreAdjustment {
        address: SocketAddress,
        new_score: u32,
    },
    Ban {
        address: BannableAddress,
    },
    Discourage {
        address: BannableAddress,
    },
    Heartbeat,
    ConnectionAccepted {
        address: SocketAddress,
        peer_role: PeerRole,
    },
}

pub struct PeerManagerObserver {
    notification_sender: UnboundedSender<PeerManagerNotification>,
}

impl PeerManagerObserver {
    pub fn new(notification_sender: UnboundedSender<PeerManagerNotification>) -> Self {
        Self {
            notification_sender,
        }
    }

    fn send_notification(&self, notification: PeerManagerNotification) {
        let send_result = self.notification_sender.send(notification.clone());

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

    fn on_peer_discouragement(&mut self, address: BannableAddress) {
        self.send_notification(PeerManagerNotification::Discourage { address });
    }

    fn on_heartbeat(&mut self) {
        self.send_notification(PeerManagerNotification::Heartbeat);
    }

    fn on_connection_accepted(&mut self, address: SocketAddress, peer_role: PeerRole) {
        self.send_notification(PeerManagerNotification::ConnectionAccepted { address, peer_role });
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestPeerInfo {
    pub info: PeerInfo,
    pub role: PeerRole,
}

#[derive(Debug, PartialEq, Eq)]
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
                ctx.peer_address,
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

    pub fn count_peers_by_ip(&self, ip: IpAddr) -> usize {
        let addr_first = SocketAddress::new(SocketAddr::new(ip, 0));
        let addr_last = SocketAddress::new(SocketAddr::new(ip, u16::MAX));
        self.info.range(addr_first..=addr_last).count()
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

pub async fn node_group_wait_for_connections_to_sock_addr<Transport>(
    node_group: &TestNodeGroup<Transport>,
    address: SocketAddress,
    min_connected_nodes_count: usize,
    iteration_time_advancement: Option<Duration>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    nodes_wait_for_connections_to_sock_addrs(
        node_group.nodes(),
        address,
        min_connected_nodes_count..=usize::MAX,
        iteration_time_advancement.map(|dur| (node_group.time_getter(), dur)),
        iteration_sleep_duration,
    )
    .await
}

pub async fn node_wait_for_connection_to_sock_addr<Transport>(
    node: &TestNode<Transport>,
    address: SocketAddress,
    iteration_time_advancement: Option<Duration>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    nodes_wait_for_connections_to_sock_addrs(
        std::slice::from_ref(node),
        address,
        1..=1,
        iteration_time_advancement.map(|dur| (node.time_getter(), dur)),
        iteration_sleep_duration,
    )
    .await
}

pub async fn node_wait_for_connection_to_ip_addr<Transport>(
    node: &TestNode<Transport>,
    address: IpAddr,
    iteration_time_advancement: Option<Duration>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    nodes_wait_for_connections_to_ip_addrs(
        std::slice::from_ref(node),
        address,
        1..=1,
        iteration_time_advancement.map(|dur| (node.time_getter(), dur)),
        iteration_sleep_duration,
    )
    .await
}

pub async fn node_wait_for_disconnection_from_ip_addr<Transport>(
    node: &TestNode<Transport>,
    address: IpAddr,
    iteration_time_advancement: Option<Duration>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    loop {
        let peers_info = node.get_peers_info().await;
        if peers_info.count_peers_by_ip(address) == 0 {
            break;
        }

        if let Some(iteration_time_advancement) = iteration_time_advancement {
            node.time_getter().advance_time(iteration_time_advancement);
        }

        if let Some(iteration_sleep_duration) = iteration_sleep_duration {
            tokio::time::sleep(iteration_sleep_duration).await;
        }
    }
}

pub async fn nodes_wait_for_connections_to_sock_addrs<Transport>(
    nodes: &[TestNode<Transport>],
    address: SocketAddress,
    required_connected_nodes_count: std::ops::RangeInclusive<usize>,
    iteration_time_advancement: Option<(&P2pBasicTestTimeGetter, Duration)>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    loop {
        let mut connected_nodes_count = 0;

        for node in nodes {
            let peers_info = node.get_peers_info().await;
            if peers_info.info.contains_key(&address) {
                connected_nodes_count += 1;
            }
        }

        if required_connected_nodes_count.contains(&connected_nodes_count) {
            break;
        }

        if let Some((time_getter, time_advancement)) = iteration_time_advancement {
            time_getter.advance_time(time_advancement);
        }

        if let Some(iteration_sleep_duration) = iteration_sleep_duration {
            tokio::time::sleep(iteration_sleep_duration).await;
        }
    }
}

pub async fn nodes_wait_for_connections_to_ip_addrs<Transport>(
    nodes: &[TestNode<Transport>],
    address: IpAddr,
    required_connected_nodes_count: std::ops::RangeInclusive<usize>,
    iteration_time_advancement: Option<(&P2pBasicTestTimeGetter, Duration)>,
    iteration_sleep_duration: Option<Duration>,
) where
    Transport: TransportSocket,
{
    loop {
        let mut connected_nodes_count = 0;

        for node in nodes {
            let peers_info = node.get_peers_info().await;
            connected_nodes_count += peers_info.count_peers_by_ip(address);
        }

        if required_connected_nodes_count.contains(&connected_nodes_count) {
            break;
        }

        if let Some((time_getter, time_advancement)) = iteration_time_advancement {
            time_getter.advance_time(time_advancement);
        }

        if let Some(iteration_sleep_duration) = iteration_sleep_duration {
            tokio::time::sleep(iteration_sleep_duration).await;
        }
    }
}
