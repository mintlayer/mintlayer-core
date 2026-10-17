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

use api_server_common::{Network, PostgresConfig};
use utils::{app_version_with_git_info, clap_utils};
use utils_networking::NetworkAddressWithPort;

#[derive(Parser)]
#[clap(mut_args(clap_utils::env_adder("API_SCANNER_DAEMON")))]
#[clap(version(app_version_with_git_info!().to_pretty_string()))]
pub struct ApiServerScannerArgs {
    /// Network
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// Optional RPC address
    #[clap(long)]
    pub node_rpc_address: Option<NetworkAddressWithPort>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub node_rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_password: Option<String>,

    /// Postgres config values
    #[clap(flatten)]
    pub postgres_config: PostgresConfig,
}

// RPC credentials and the database password must never appear in debug output; a debug
// dump of the whole struct is therefore safe by construction.
impl std::fmt::Debug for ApiServerScannerArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiServerScannerArgs")
            .field("network", &self.network)
            .field("node_rpc_address", &self.node_rpc_address)
            .field("node_rpc_cookie_file", &self.node_rpc_cookie_file)
            .field(
                "node_rpc_username",
                &self.node_rpc_username.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "node_rpc_password",
                &self.node_rpc_password.as_ref().map(|_| "<redacted>"),
            )
            .field("postgres_config", &self.postgres_config)
            .finish()
    }
}

impl ApiServerScannerArgs {
    /// A loggable summary of the options, omitting every value that can hold a secret.
    /// Keep this method, not a struct dump, in log statements.
    pub fn redacted_summary(&self) -> String {
        // PostgresConfig's Debug output redacts the database password.
        format!(
            "network: {:?}, node RPC address: {:?}, node RPC cookie file: {:?}, postgres: {:?}",
            self.network, self.node_rpc_address, self.node_rpc_cookie_file, self.postgres_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_summary_omits_secrets() {
        let args = ApiServerScannerArgs::parse_from([
            "scanner-daemon",
            "--node-rpc-username",
            "alice",
            "--node-rpc-password",
            "supersecret",
            "--postgres-password",
            "dbsecret",
        ]);
        let summary = args.redacted_summary();
        assert!(summary.contains("network: Mainnet"));
        assert!(summary.contains("node RPC address: None"));
        assert!(summary.contains("node RPC cookie file: None"));
        assert!(summary.contains("postgres"));
        assert!(summary.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!summary.contains("alice"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("dbsecret"));
        let debug_dump = format!("{args:?}");
        assert!(debug_dump.contains("ApiServerScannerArgs"));
        assert!(debug_dump.contains("node_rpc_password: Some(\"<redacted>\")"));
        assert!(debug_dump.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!debug_dump.contains("alice"));
        assert!(!debug_dump.contains("supersecret"));
        assert!(!debug_dump.contains("dbsecret"));
    }
}
