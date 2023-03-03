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

use clap::Parser;
use directories::BaseDirs;
use trust_dns_client::rr::Name;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Parser, Debug)]
pub struct DnsServerConfig {
    /// The path to the data directory
    #[clap(long, default_value_t = default_data_dir())]
    pub datadir: String,

    /// Network
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// UDP socket address to listen on. Can be specified multiple times.
    #[clap(long, default_values_t = vec!["[::]:53".to_string()])]
    pub bind_addr: Vec<String>,

    /// Reserved node address to connect. Can be specified multiple times.
    #[clap(long)]
    pub reserved_node: Vec<String>,

    /// Hostname of the DNS seed
    #[clap(long)]
    pub host: Name,

    /// Hostname of the nameserver.
    /// If set, the NS record will be added.
    #[clap(long)]
    pub nameserver: Option<Name>,

    /// Email address reported in SOA records.
    /// `@` symbol should be replaced with `.`.
    /// If set, the SOA record will be added.
    #[clap(long)]
    pub mbox: Option<Name>,
}

const DEFAULT_DATA_DIR_NAME: &str = "mintlayer_dns_server";

fn default_data_dir() -> String {
    BaseDirs::new()
        .expect("BaseDirs build failed")
        .data_dir()
        .join(DEFAULT_DATA_DIR_NAME)
        .to_str()
        .expect("expected valid default data dir path")
        .to_owned()
}
