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
use directories::UserDirs;

#[derive(Parser, Debug)]
pub struct DnsServerConfig {
    /// The path to the data directory
    #[clap(long, default_value_t = default_data_dir())]
    pub datadir: String,

    /// Use testnet
    #[clap(long)]
    pub testnet: bool,

    /// IP address and UDP port to listen on
    #[clap(long, default_values_t = vec!["[::]:53".to_string()])]
    pub bind_addr: Vec<String>,

    /// Optional list of initial node addresses to connect
    #[clap(long)]
    pub add_node: Vec<String>,

    /// Hostname of the DNS seed
    #[clap(long)]
    pub host: String,

    /// Hostname of the nameserver
    #[clap(long)]
    pub ns: String,

    /// E-Mail address reported in SOA records (RNAME)
    #[clap(long)]
    pub mbox: String,
}

const DEFAULT_DATA_DIR_NAME: &str = ".mintlayer";

fn default_data_dir() -> String {
    UserDirs::new()
        .expect("Unable to get home directory")
        .home_dir()
        .join(DEFAULT_DATA_DIR_NAME)
        .to_str()
        .expect("expected valid default data dir path")
        .to_owned()
}
