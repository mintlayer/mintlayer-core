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

use std::time::Duration;

use tokio::time;

use ::test_utils::BasicTestTimeGetter;
use common::{chain::Block, primitives::Id};
use networking::transport::TransportSocket;
use p2p_test_utils::SHORT_TIMEOUT;
use p2p_types::socket_address::SocketAddress;

use crate::{config::P2pConfig, net::types::PeerRole};

use super::test_node::TestNode;

pub struct TestNodeGroup<Transport>
where
    Transport: TransportSocket,
{
    nodes: Vec<TestNode<Transport>>,
}

impl<Transport> TestNodeGroup<Transport>
where
    Transport: TransportSocket,
{
    pub fn new(nodes: Vec<TestNode<Transport>>) -> Self {
        assert!(!nodes.is_empty());
        for i in 1..nodes.len() {
            assert!(std::ptr::eq(nodes[0].p2p_config(), nodes[i].p2p_config()));
            assert!(nodes[0].time_getter().is_same_instance(nodes[i].time_getter()));
        }

        Self { nodes }
    }

    pub fn nodes(&self) -> &[TestNode<Transport>] {
        &self.nodes
    }

    pub fn time_getter(&self) -> &BasicTestTimeGetter {
        self.nodes[0].time_getter()
    }

    #[allow(unused)]
    pub fn p2p_config(&self) -> &P2pConfig {
        self.nodes[0].p2p_config()
    }

    pub fn get_adresses(&self) -> Vec<SocketAddress> {
        self.nodes.iter().map(|node| *node.local_address()).collect()
    }

    pub async fn count_connections_by_role(&self, peer_role: PeerRole) -> Vec<usize> {
        let mut result = Vec::with_capacity(self.nodes.len());

        for node in &self.nodes {
            let peers_info = node.get_peers_info().await.info;
            let count =
                peers_info.iter().filter(|(_, peer_info)| peer_info.role == peer_role).count();

            result.push(count);
        }

        result
    }

    #[allow(unused)]
    pub async fn assert_outbound_conn_count_maximums_reached(&self) {
        for node in &self.nodes {
            node.assert_outbound_conn_count_maximums_reached().await;
        }
    }

    pub fn set_dns_seed_addresses(&self, addresses: &[SocketAddress]) {
        for node in &self.nodes {
            node.set_dns_seed_addresses(addresses.to_vec());
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
                    .call(move |cs| cs.get_block(&block_id))
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
            self.time_getter().advance_time(time_diff);
        }
    }

    pub async fn join(self) {
        for node in self.nodes {
            node.join().await;
        }
    }
}
