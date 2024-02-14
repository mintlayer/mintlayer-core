// Copyright (c) 2022 RBB S.r.l
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

use std::{net::IpAddr, num::NonZeroU64, str::FromStr, time::Duration};

use common::primitives::user_agent::mintlayer_core_user_agent;
use serde::{Deserialize, Serialize};

use p2p::{
    ban_config::BanConfig,
    config::{NodeType, P2pConfig},
    peer_manager::config::PeerManagerConfig,
};
use utils_tokio::IpOrSocketAddress;

/// A node type.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum NodeTypeConfigFile {
    /// A full node.
    #[serde(rename = "full-node", alias = "full")]
    FullNode,
    /// A node that only download blocks, but ignores transactions.
    #[serde(rename = "blocks-only-node", alias = "blocks")]
    BlocksOnlyNode,
}

impl From<NodeTypeConfigFile> for NodeType {
    fn from(t: NodeTypeConfigFile) -> Self {
        match t {
            NodeTypeConfigFile::FullNode => Self::Full,
            NodeTypeConfigFile::BlocksOnlyNode => Self::BlocksOnly,
        }
    }
}

impl FromStr for NodeTypeConfigFile {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de = serde::de::value::StrDeserializer::new(s);
        Deserialize::deserialize(de)
    }
}

/// The p2p subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct P2pConfigFile {
    /// Address to bind P2P to.
    pub bind_addresses: Option<Vec<String>>,
    /// SOCKS5 proxy.
    pub socks5_proxy: Option<String>,
    /// Disable p2p encryption (for tests only).
    pub disable_noise: Option<bool>,
    /// Optional list of boot node addresses to connect.
    pub boot_nodes: Option<Vec<IpOrSocketAddress>>,
    /// Optional list of reserved node addresses to connect.
    pub reserved_nodes: Option<Vec<IpOrSocketAddress>>,
    /// Optional list of whitelisted addresses.
    pub whitelisted_addresses: Option<Vec<IpAddr>>,
    /// Maximum allowed number of inbound connections.
    pub max_inbound_connections: Option<usize>,
    /// The score threshold after which a peer becomes discouraged.
    pub discouragement_threshold: Option<u32>,
    /// Duration of discouragement in seconds.
    pub discouragement_duration: Option<u64>,
    /// Maximum acceptable time difference between this node and the remote peer (in seconds).
    /// If a large difference is detected, the peer will be disconnected.
    pub max_clock_diff: Option<u64>,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: Option<NonZeroU64>,
    /// How often send ping requests to peers.
    pub ping_check_period: Option<u64>,
    /// When a peer is detected as dead and disconnected.
    pub ping_timeout: Option<NonZeroU64>,
    /// A timeout after which a peer is disconnected.
    pub sync_stalling_timeout: Option<NonZeroU64>,
    /// A node type.
    pub node_type: Option<NodeTypeConfigFile>,
    /// If true, the node will perform an early dns query if the peer db doesn't contain
    /// any global addresses at startup.
    pub force_dns_query_if_no_global_addresses_known: Option<bool>,
}

impl From<P2pConfigFile> for P2pConfig {
    fn from(config_file: P2pConfigFile) -> Self {
        let P2pConfigFile {
            bind_addresses,
            socks5_proxy,
            disable_noise,
            boot_nodes,
            reserved_nodes,
            whitelisted_addresses,
            max_inbound_connections,
            discouragement_threshold,
            discouragement_duration,
            max_clock_diff,
            outbound_connection_timeout,
            ping_check_period,
            ping_timeout,
            sync_stalling_timeout,
            node_type,
            force_dns_query_if_no_global_addresses_known,
        } = config_file;

        P2pConfig {
            bind_addresses: bind_addresses.unwrap_or_default(),
            socks5_proxy,
            disable_noise,
            boot_nodes: boot_nodes.unwrap_or_default(),
            reserved_nodes: reserved_nodes.unwrap_or_default(),
            whitelisted_addresses: whitelisted_addresses.unwrap_or_default(),
            ban_config: BanConfig {
                discouragement_threshold: discouragement_threshold.into(),
                discouragement_duration: discouragement_duration.map(Duration::from_secs).into(),
            },
            max_clock_diff: max_clock_diff.map(Duration::from_secs).into(),
            outbound_connection_timeout: outbound_connection_timeout
                .map(|t| Duration::from_secs(t.into()))
                .into(),
            ping_check_period: ping_check_period.map(Duration::from_secs).into(),
            ping_timeout: ping_timeout.map(|t| Duration::from_secs(t.into())).into(),
            node_type: node_type.map(Into::into).into(),

            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: sync_stalling_timeout
                .map(|t| Duration::from_secs(t.into()))
                .into(),
            peer_manager_config: PeerManagerConfig {
                max_inbound_connections: max_inbound_connections.into(),

                preserved_inbound_count_address_group: Default::default(),
                preserved_inbound_count_ping: Default::default(),
                preserved_inbound_count_new_blocks: Default::default(),
                preserved_inbound_count_new_transactions: Default::default(),

                outbound_full_relay_count: Default::default(),
                outbound_full_relay_extra_count: Default::default(),
                outbound_block_relay_count: Default::default(),
                outbound_block_relay_extra_count: Default::default(),

                outbound_block_relay_connection_min_age: Default::default(),
                outbound_full_relay_connection_min_age: Default::default(),

                stale_tip_time_diff: Default::default(),
                main_loop_tick_interval: Default::default(),

                enable_feeler_connections: Default::default(),
                feeler_connections_interval: Default::default(),

                force_dns_query_if_no_global_addresses_known:
                    force_dns_query_if_no_global_addresses_known.into(),

                allow_same_ip_connections: Default::default(),

                peerdb_config: Default::default(),
            },
            protocol_config: Default::default(),
            peer_handshake_timeout: Default::default(),
        }
    }
}
