// Copyright (c) 2023 RBB S.r.l
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

use std::path::PathBuf;

use clap::Parser;
use trust_dns_client::rr::Name;

use common::primitives::per_thousand::PerThousand;
use p2p::types::ip_or_socket_address::IpOrSocketAddress;

use crate::dns_server::MinSameSoftwareVersionNodesRatio;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Parser, Debug)]
pub struct DnsServerConfig {
    /// Optional path to the data directory
    #[clap(long, env = "MINTLAYER_DATADIR")]
    pub datadir: Option<PathBuf>,

    /// Network
    #[arg(long, value_enum, default_value_t = Network::Mainnet, env = "MINTLAYER_NETWORK")]
    pub network: Network,

    /// UDP socket addresses to listen on.
    /// Can be specified multiple times and/or be a comma-separated list.
    #[clap(
        long,
        default_values_t = vec!["[::]:53".to_string()],
        value_delimiter(','),
        env = "MINTLAYER_BIND_ADDR"
    )]
    pub bind_addr: Vec<String>,

    /// Reserved node addresses to connect.
    /// Can be specified multiple times and/or be a comma-separated list.
    #[clap(long, value_delimiter(','), env = "MINTLAYER_RESERVED_NODES")]
    pub reserved_nodes: Vec<IpOrSocketAddress>,

    /// Hostname of the DNS seed
    #[clap(long, env = "MINTLAYER_HOST")]
    pub host: Name,

    /// Hostname of the nameserver.
    /// If set, the NS record will be added.
    #[clap(long, env = "MINTLAYER_NAMESERVER")]
    pub nameserver: Option<Name>,

    /// Email address reported in SOA records.
    /// `@` symbol should be replaced with `.`.
    /// If set, the SOA record will be added.
    #[clap(long, env = "MINTLAYER_MBOX")]
    pub mbox: Option<Name>,

    /// When publishing addresses, we give preference to nodes that have the same software version
    /// as the dns server itself.
    /// This parameter determines how many addresses of same-version nodes will be published
    /// compared to the total number of addresses.
    #[clap(
        long,
        value_name = "PER_THOUSAND",
        value_parser(PerThousand::from_decimal_str),
        default_value_t = *MinSameSoftwareVersionNodesRatio::default()
    )]
    pub min_same_software_version_nodes_ratio: PerThousand,
}
