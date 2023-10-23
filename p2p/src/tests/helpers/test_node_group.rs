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

use std::{collections::BTreeSet, time::Duration};

use common::{chain::Block, primitives::Id};
use futures::{future::select_all, FutureExt};
use logging::log;
use p2p_test_utils::{P2pBasicTestTimeGetter, SHORT_TIMEOUT};
use p2p_types::socket_address::SocketAddress;
use tokio::time;

use crate::net::default_backend::transport::TransportSocket;

use super::{test_node::TestNode, PeerManagerNotification};

pub struct TestNodeGroup<Transport>
where
    Transport: TransportSocket,
{
    nodes: Vec<TestNode<Transport>>,
    time_getter: P2pBasicTestTimeGetter,
}

impl<Transport> TestNodeGroup<Transport>
where
    Transport: TransportSocket,
{
    pub fn new(nodes: Vec<TestNode<Transport>>, time_getter: P2pBasicTestTimeGetter) -> Self {
        Self { nodes, time_getter }
    }

    pub fn nodes(&self) -> &[TestNode<Transport>] {
        &self.nodes
    }

    pub fn time_getter(&self) -> &P2pBasicTestTimeGetter {
        &self.time_getter
    }

    pub fn get_adresses(&self) -> Vec<SocketAddress> {
        self.nodes.iter().map(|node| *node.local_address()).collect()
    }

    pub fn set_dns_seed_addresses(&self, addresses: &Vec<SocketAddress>) {
        for node in &self.nodes {
            node.set_dns_seed_addresses(addresses.clone());
        }
    }

    pub async fn recv_peer_mgr_notification(&mut self) -> (usize, PeerManagerNotification) {
        let combined_future = select_all(
            self.nodes
                .iter_mut()
                .map(|node| node.recv_peer_mgr_notification().boxed())
                .collect::<Vec<_>>(),
        );
        let (notification, future_idx, _) = combined_future.await;
        (future_idx, notification.unwrap())
    }

    // Wait for one heartbeat for each node. The caller code must make sure that the
    // time is advanced appropriately, so that heartbeats actually happen.
    pub async fn wait_for_peer_mgr_heartbeat(&mut self) {
        for node in &mut self.nodes {
            node.wait_for_peer_mgr_heartbeat().await;
        }
    }

    // Wait until the specified number of nodes has been connected to the specified address.
    pub async fn wait_for_connection_advance_time(
        &mut self,
        nodes_count: usize,
        address: SocketAddress,
        time_diff: Duration,
    ) {
        assert!(nodes_count <= self.nodes.len());
        let mut connected = BTreeSet::new();

        while connected.len() < nodes_count {
            if let Ok((node_idx, notification)) =
                // Note: SHORT_TIMEOUT is still too big here, it'll just introduce useless
                // delays when there are no notifications in flight and producing new ones
                // requires the time to be advanced.
                time::timeout(SHORT_TIMEOUT / 10, self.recv_peer_mgr_notification()).await
            {
                let expected_notification = PeerManagerNotification::ConnectionAccepted { address };
                if notification == expected_notification {
                    connected.insert(node_idx);
                    log::debug!(
                        "Got a connection to {address}, the total connections count is {}",
                        connected.len()
                    );
                }
            } else {
                self.time_getter.advance_time(time_diff);
            }
        }
    }

    // Wait until the specified block has been propagated to the specified number of nodes.
    pub async fn wait_for_block_propagation_advance_time(
        &self,
        nodes_count: usize,
        block_id: Id<Block>,
        time_diff: Duration,
    ) {
        let mut cur_nodes_count = 0;

        loop {
            let prev_nodes_count = cur_nodes_count;
            cur_nodes_count = 0;

            for node in &self.nodes {
                let block = node
                    .chainstate()
                    .call(move |cs| cs.get_block(block_id))
                    .await
                    .unwrap()
                    .unwrap();
                if block.is_some() {
                    cur_nodes_count += 1;
                }
            }

            if cur_nodes_count != prev_nodes_count {
                println!("Block {block_id} has been propagated to {cur_nodes_count} nodes");
            }

            if cur_nodes_count >= nodes_count {
                break;
            }

            time::sleep(SHORT_TIMEOUT).await;
            self.time_getter.advance_time(time_diff);
        }
    }

    pub async fn join(self) {
        for node in self.nodes {
            node.join().await;
        }
    }
}
