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

use p2p::config::{MdnsConfig, P2pConfig};
use serde::{Deserialize, Serialize};

pub const MDNS_DEFAULT_QUERY_INTERVAL: u64 = 0;
pub const MDNS_DEFAULT_IPV6_STATE: bool = false;

/// Multicast DNS configuration.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "state")]
pub enum MdnsConfigFile {
    Enabled {
        /// Interval (in milliseconds) at which to poll the network for new peers.
        query_interval: u64,
        /// Use IPv6 for multicast DNS
        enable_ipv6_mdns_discovery: bool,
    },
    Disabled,
}

impl MdnsConfigFile {
    pub fn new() -> Self {
        MdnsConfigFile::Disabled
    }

    pub fn from_options(
        enable_mdns: bool,
        query_interval: Option<u64>,
        enable_ipv6_mdns_discovery: Option<bool>,
    ) -> Self {
        if enable_mdns {
            MdnsConfigFile::Enabled {
                query_interval: query_interval.unwrap_or(MDNS_DEFAULT_QUERY_INTERVAL),
                enable_ipv6_mdns_discovery: enable_ipv6_mdns_discovery
                    .unwrap_or(MDNS_DEFAULT_IPV6_STATE),
            }
        } else {
            // TODO: make the check for these automatic
            assert!(
                query_interval.is_none(),
                "mDNS is disabled but query interval is specified"
            );
            assert!(
                enable_ipv6_mdns_discovery.is_none(),
                "mDNS is disabled but transport over IPv6 is enabled"
            );

            MdnsConfigFile::Disabled
        }
    }
}

impl From<MdnsConfigFile> for MdnsConfig {
    fn from(c: MdnsConfigFile) -> Self {
        match c {
            MdnsConfigFile::Enabled {
                query_interval,
                enable_ipv6_mdns_discovery,
            } => MdnsConfig::Enabled {
                query_interval: query_interval.into(),
                enable_ipv6_mdns_discovery: enable_ipv6_mdns_discovery.into(),
            },
            MdnsConfigFile::Disabled => MdnsConfig::Disabled,
        }
    }
}

// TODO(PR) make all members option
/// The p2p subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct P2pConfigFile {
    /// Address to bind P2P to.
    pub bind_address: String,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: u32,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: u64,
    /// Multicast DNS configuration.
    pub mdns_config: MdnsConfigFile,
}

impl From<P2pConfigFile> for P2pConfig {
    fn from(c: P2pConfigFile) -> Self {
        let mdns_config: MdnsConfig = c.mdns_config.into();
        P2pConfig {
            bind_address: c.bind_address.into(),
            ban_threshold: c.ban_threshold.into(),
            outbound_connection_timeout: c.outbound_connection_timeout.into(),
            mdns_config: mdns_config.into(),
        }
    }
}

impl Default for P2pConfigFile {
    fn default() -> Self {
        Self {
            bind_address: "/ip6/::1/tcp/3031".into(),
            ban_threshold: 100,
            outbound_connection_timeout: 10,
            mdns_config: MdnsConfigFile::Disabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn mdsn_disabled_but_query_interval_specified() {
        MdnsConfigFile::from_options(false, Some(200), None);
    }

    #[test]
    #[should_panic]
    fn mdsn_disabled_but_ipv6_enabled() {
        MdnsConfigFile::from_options(false, None, Some(true));
    }
}
