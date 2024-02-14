// Copyright (c) 2021-2024 RBB S.r.l
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

use utils::make_config_setting;

use super::{
    peerdb::config::PeerDbConfig,
    peers_eviction::{
        OutboundBlockRelayConnectionMinAge, OutboundFullRelayConnectionMinAge,
        PreservedInboundCountAddressGroup, PreservedInboundCountNewBlocks,
        PreservedInboundCountNewTransactions, PreservedInboundCountPing,
    },
};

make_config_setting!(MaxInboundConnections, usize, 128);
make_config_setting!(OutboundFullRelayCount, usize, 8);
make_config_setting!(OutboundFullRelayExtraCount, usize, 1);
make_config_setting!(OutboundBlockRelayCount, usize, 2);
make_config_setting!(OutboundBlockRelayExtraCount, usize, 1);
make_config_setting!(StaleTipTimeDiff, Duration, Duration::from_secs(30 * 60));
make_config_setting!(MainLoopTickInterval, Duration, Duration::from_secs(1));
make_config_setting!(
    FeelerConnectionsInterval,
    Duration,
    Duration::from_secs(2 * 60)
);
make_config_setting!(EnableFeelerConnections, bool, true);
make_config_setting!(ForceDnsQueryIfNoGlobalAddressesKnown, bool, false);
make_config_setting!(AllowSameIpConnections, bool, false);

// TODO: this name is too generic, because not all peer manager settings are contained here.
// PeerManagerInternalConfig might be a better name (though there are objections against it,
// see https://github.com/mintlayer/mintlayer-core/pull/1451#discussion_r1453407430).
// Alternatively, we may want to actually put all peer manager settings here. If we do this,
// it might be better to revise the entire structure of p2p config and make it more hierarchical.
// E.g. we may have separate structs for backend, sync manager and peer manager settings at the
// top level; then, eviction settings in PeerManagerConfig may go to their separate struct, etc.
#[derive(Default, Debug, Clone)]
pub struct PeerManagerConfig {
    /// Maximum allowed number of inbound connections.
    pub max_inbound_connections: MaxInboundConnections,

    /// The number of inbound peers to preserve based on the address group.
    pub preserved_inbound_count_address_group: PreservedInboundCountAddressGroup,
    /// The number of inbound peers to preserve based on ping.
    pub preserved_inbound_count_ping: PreservedInboundCountPing,
    /// The number of inbound peers to preserve based on the last time they sent us new blocks.
    pub preserved_inbound_count_new_blocks: PreservedInboundCountNewBlocks,
    /// The number of inbound peers to preserve based on the last time they sent us new transactions.
    pub preserved_inbound_count_new_transactions: PreservedInboundCountNewTransactions,

    /// The desired maximum number of full relay outbound connections.
    /// Note that this limit may be exceeded temporarily by up to outbound_full_relay_extra_count
    /// connections.
    pub outbound_full_relay_count: OutboundFullRelayCount,
    /// The number of extra full relay connections that we may establish when a stale tip
    /// is detected.
    pub outbound_full_relay_extra_count: OutboundFullRelayExtraCount,

    /// The desired maximum number of block relay outbound connections.
    /// Note that this limit may be exceeded temporarily by up to outbound_block_relay_extra_count
    /// connections.
    pub outbound_block_relay_count: OutboundBlockRelayCount,
    /// The number of extra block relay connections that we will establish and evict regularly.
    pub outbound_block_relay_extra_count: OutboundBlockRelayExtraCount,

    /// Outbound block relay connections younger than this age will not be taken into account
    /// during eviction.
    /// Note that extra block relay connections are established and evicted on a regular basis
    /// during normal operation. So, this interval basically determines how often those extra
    /// connections will come and go.
    pub outbound_block_relay_connection_min_age: OutboundBlockRelayConnectionMinAge,
    /// Outbound full relay connections younger than this age will not be taken into account
    /// during eviction.
    /// Note that extra full relay connections are established if the current tip becomes stale.
    pub outbound_full_relay_connection_min_age: OutboundFullRelayConnectionMinAge,

    /// The time after which the tip will be considered stale.
    pub stale_tip_time_diff: StaleTipTimeDiff,

    /// How often the main loop should be woken up when no other events occur.
    pub main_loop_tick_interval: MainLoopTickInterval,

    /// Whether feeler connections should be enabled.
    pub enable_feeler_connections: EnableFeelerConnections,
    /// The minimum interval between feeler connections.
    pub feeler_connections_interval: FeelerConnectionsInterval,

    /// If true, the node will perform an early dns query if the peer db doesn't contain
    /// any global addresses at startup (more precisely, the ones for which is_global_unicast_ip
    /// returns true).
    ///
    /// Note that this is mainly needed to speed up the startup of the test
    /// nodes in build-tools/p2p-test. Those nodes always start with a boot_nodes
    /// list that contains addresses of their siblings, which are always some private ips;
    /// therefore, they all will have peers from the beginning, which will prevent normal
    /// dns queries, but will be unable to obtain blocks until stale_tip_time_diff has elapsed,
    /// which is 30 min by default. Setting this option to true will force the peer manager
    /// to perform an early dns query in such a situation.
    pub force_dns_query_if_no_global_addresses_known: ForceDnsQueryIfNoGlobalAddressesKnown,

    /// If true, multiple connections to the same ip address (but using a different port) will
    /// always be allowed.
    ///
    /// Normally, the peer manager won't always allow connecting to the same ip using a different
    /// port; e.g. if an inbound connection exists, a new outbound connection to the same ip
    /// will only be allowed if it's manual. This may be inconvenient for some (legacy) unit tests,
    /// so they can set this option to true to override this behavior.
    /// TODO: consider rewriting tests that need this option and remove it.
    pub allow_same_ip_connections: AllowSameIpConnections,

    /// Peer db configuration.
    pub peerdb_config: PeerDbConfig,
}

impl PeerManagerConfig {
    pub fn total_preserved_inbound_count(&self) -> usize {
        *self.preserved_inbound_count_address_group
            + *self.preserved_inbound_count_ping
            + *self.preserved_inbound_count_new_blocks
            + *self.preserved_inbound_count_new_transactions
    }

    /// The desired maximum number of automatic outbound connections.
    pub fn outbound_full_and_block_relay_count(&self) -> usize {
        *self.outbound_full_relay_count + *self.outbound_block_relay_count
    }
}
