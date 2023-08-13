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

use std::time::Duration;

use common::primitives::user_agent::{mintlayer_core_user_agent, UserAgent};
use p2p_types::ip_or_socket_address::IpOrSocketAddress;
use utils::make_config_setting;

use crate::net::types::services::{Service, Services};

make_config_setting!(MaxInboundConnections, usize, 128);
make_config_setting!(BanThreshold, u32, 100);
make_config_setting!(BanDuration, Duration, Duration::from_secs(60 * 60 * 24));
make_config_setting!(OutboundConnectionTimeout, Duration, Duration::from_secs(10));
make_config_setting!(NodeTypeSetting, NodeType, NodeType::Full);
make_config_setting!(AllowDiscoverPrivateIps, bool, false);
make_config_setting!(PingCheckPeriod, Duration, Duration::from_secs(60));
make_config_setting!(PingTimeout, Duration, Duration::from_secs(150));
make_config_setting!(MaxClockDiff, Duration, Duration::from_secs(10));
make_config_setting!(HeaderLimit, usize, 2000);
make_config_setting!(MaxLocatorSize, usize, 101);
make_config_setting!(RequestedBlocksLimit, usize, 500);
make_config_setting!(MaxMessageSize, usize, 10 * 1024 * 1024);
make_config_setting!(MaxPeerTxAnnouncements, usize, 5000);
make_config_setting!(MaxUnconnectedHeaders, usize, 10);
make_config_setting!(SyncStallingTimeout, Duration, Duration::from_secs(5));

/// A node type.
#[derive(Debug, Copy, Clone)]
pub enum NodeType {
    /// A full node.
    Full,
    /// A node that only download blocks, but ignores transactions.
    BlocksOnly,
    /// A node interested only in network address announcements.
    DnsServer,
    /// A node that doesn't subscribe to any events.
    ///
    /// This node type isn't useful outside of the tests.
    Inactive,
}

impl From<NodeType> for Services {
    fn from(t: NodeType) -> Self {
        match t {
            NodeType::Full => [Service::Blocks, Service::Transactions, Service::PeerAddresses]
                .as_slice()
                .into(),
            NodeType::BlocksOnly => [Service::Blocks].as_slice().into(),
            NodeType::DnsServer => [Service::PeerAddresses].as_slice().into(),
            NodeType::Inactive => [].as_slice().into(),
        }
    }
}

/// The p2p subsystem configuration.
// TODO: some of these "configuration options" should never be changed in production code,
// because their values are a part of the protocol, e.g. this includes msg_header_count_limit and
// max_request_blocks_count. Some other, like msg_max_locator_count, are never changed even
// in tests. It might be better to separate these "settings" off into a separate struct and/or
// make some of them constants (and the constant corresponding to msg_max_locator_count may
// even be moved to chainstate, where locators are actually produced).
#[derive(Debug)]
pub struct P2pConfig {
    /// Address to bind P2P to.
    pub bind_addresses: Vec<String>,
    /// SOCKS5 proxy.
    pub socks5_proxy: Option<String>,
    /// Disable p2p encryption (for tests only).
    pub disable_noise: Option<bool>,
    /// Optional list of initial node addresses.
    /// Boot node addresses are added to PeerDb as regular discovered addresses.
    pub boot_nodes: Vec<IpOrSocketAddress>,
    /// Optional list of reserved node addresses.
    /// PeerManager will try to maintain persistent connections to the reserved nodes.
    /// Ban scores are not adjusted for the reserved nodes.
    pub reserved_nodes: Vec<IpOrSocketAddress>,
    /// Maximum allowed number of inbound connections.
    pub max_inbound_connections: MaxInboundConnections,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: BanThreshold,
    /// Duration of bans in seconds.
    pub ban_duration: BanDuration,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: OutboundConnectionTimeout,
    /// How often send ping requests to peers
    pub ping_check_period: PingCheckPeriod,
    /// When a peer is detected as dead and disconnected
    pub ping_timeout: PingTimeout,
    /// Maximum acceptable time difference between this node and the remote peer.
    /// If a large difference is detected, the peer will be disconnected.
    pub max_clock_diff: MaxClockDiff,
    /// A node type.
    pub node_type: NodeTypeSetting,
    /// Allow announcing and discovering local and private IPs. Should be used for testing only.
    pub allow_discover_private_ips: AllowDiscoverPrivateIps,
    /// A maximum allowed number of headers in one message.
    pub msg_header_count_limit: HeaderLimit,
    /// A maximum number of the elements in the locator.
    pub msg_max_locator_count: MaxLocatorSize,
    /// A maximum number of blocks that can be requested from a single peer.
    pub max_request_blocks_count: RequestedBlocksLimit,
    /// User agent value of this node (sent to peers over the network).
    pub user_agent: UserAgent,
    /// A maximum size of a p2p message in bytes.
    pub max_message_size: MaxMessageSize,
    /// A maximum number of announcements (hashes) for which we haven't receive transactions.
    pub max_peer_tx_announcements: MaxPeerTxAnnouncements,
    /// A maximum number of singular unconnected headers that a peer can send before
    /// it will be considered malicious.
    // TODO: this is a legacy behavior that should be removed in the protocol v2.
    pub max_singular_unconnected_headers: MaxUnconnectedHeaders,
    /// A timeout after which a peer is disconnected.
    pub sync_stalling_timeout: SyncStallingTimeout,
}

impl P2pConfig {
    pub fn new() -> Self {
        P2pConfig {
            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            max_inbound_connections: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            msg_header_count_limit: Default::default(),
            msg_max_locator_count: Default::default(),
            max_request_blocks_count: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
            max_singular_unconnected_headers: Default::default(),
            sync_stalling_timeout: Default::default(),
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self::new()
    }
}
