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


use api_server_common::{Network, PostgresConfig};
use utils_networking::NetworkAddressWithPort;

use clap::Parser;

use api_server_common::{Network, PostgresConfig};
use utils::clap_utils;

#[derive(Parser, Debug)]
#[clap(mut_args(clap_utils::env_adder("API_SCANNER_DAEMON")))]
pub struct ApiServerScannerArgs {
    /// Network
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// Optional RPC address
    #[clap(long)]
    pub rpc_address: Option<NetworkAddressWithPort>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_password: Option<String>,

    /// Postgres config values
    #[clap(flatten)]
    pub postgres_config: PostgresConfig,
}
