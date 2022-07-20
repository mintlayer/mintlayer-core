// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use serde::{Deserialize, Serialize};

/// The p2p subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct P2pConfig {
    /// Address to bind P2P to.
    pub bind_address: String,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: u32,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: u64,
    /// Enable multicast DNS peer discovery.
    pub enable_mdns: bool,
    /// Interval (in milliseconds) at which to poll the network for new peers.
    pub mdns_query_interval: u64,
    /// Use IPv6 for multicast DNS
    pub mdns_enable_ipv6: bool,
}

impl P2pConfig {
    /// Creates a new p2p configuration instance.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bind_address: "/ip6/::1/tcp/3031".into(),
            ban_threshold: 100,
            outbound_connection_timeout: 10,
            enable_mdns: false,
            mdns_query_interval: 0,
            mdns_enable_ipv6: false,
        }
    }
}
