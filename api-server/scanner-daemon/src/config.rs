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

use api_server_common::{Network, PostgresConfig, RedactedSummary, redact};
use utils::{app_version_with_git_info, clap_utils};
use utils_networking::NetworkAddressWithPort;

/// Options whose values can hold a secret; their environment-sourced values are hidden
/// from the help output.
// NOTE: when adding a secret-bearing field to this struct, update BOTH the Debug impl
// below (the exhaustive destructure enforces this) AND this list (nothing enforces it;
// the classification check in the guard test rejects omissions: any new option left
// out of both SECRET_OPTIONS and NON_SECRET_OPTIONS fails the test, though it cannot
// tell which list an option belongs in). A secret-bearing field
// added to the flattened `PostgresConfig` escapes the destructure here: it is guarded
// by `PostgresConfig`'s own Debug impl in api-server-common, but it must still be
// added to this list.
const SECRET_OPTIONS: &[&str] = &["node-rpc-username", "node-rpc-password", "postgres-password"];

#[derive(Parser)]
#[clap(mut_args(clap_utils::env_adder_hiding_env_values("API_SCANNER_DAEMON", SECRET_OPTIONS)))]
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
        // Destructure without `..` so a newly added field fails to compile until it is either
        // added here or shown to be safe.
        let Self {
            network,
            node_rpc_address,
            node_rpc_cookie_file,
            node_rpc_username,
            node_rpc_password,
            postgres_config,
        } = self;
        f.debug_struct("ApiServerScannerArgs")
            .field("network", network)
            .field("node_rpc_address", node_rpc_address)
            .field("node_rpc_cookie_file", node_rpc_cookie_file)
            .field("node_rpc_username", &redact(node_rpc_username))
            .field("node_rpc_password", &redact(node_rpc_password))
            .field("postgres_config", postgres_config)
            .finish()
    }
}

// The hand-written Debug impl redacts the secret-bearing fields and guards new fields
// with an exhaustive destructure, so the summary is the Debug output itself.
impl RedactedSummary for ApiServerScannerArgs {
    fn redacted_summary(&self) -> String {
        format!("{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_server_common::REDACTED;
    use clap::CommandFactory;

    #[test]
    fn secret_options_are_hidden_from_help() {
        let cmd = ApiServerScannerArgs::command();
        // Options explicitly classified as non-secret; anything else must be listed in
        // SECRET_OPTIONS or the classification check below fails.
        const NON_SECRET_OPTIONS: &[&str] = &[
            "network",
            "node-rpc-address",
            "node-rpc-cookie-file",
            "postgres-host",
            "postgres-port",
            "postgres-user",
            "postgres-database",
            "postgres-max-connections",
        ];
        // Every option must be classified as secret or non-secret; the helper includes
        // the secret pin above and rejects stale non-secret entries.
        clap_utils::assert_options_classified(&cmd, SECRET_OPTIONS, NON_SECRET_OPTIONS);
    }

    #[test]
    fn redacted_summary_omits_secrets() {
        // Built directly so no ML_API_SCANNER_DAEMON_* environment fallback applies.
        let args = ApiServerScannerArgs {
            network: Network::Mainnet,
            node_rpc_address: Some("127.0.0.1:12345".parse().unwrap()),
            node_rpc_cookie_file: Some("/tmp/rpc-cookie-file".to_string()),
            node_rpc_username: Some("alice".to_string()),
            node_rpc_password: Some("supersecret".to_string()),
            postgres_config: PostgresConfig {
                postgres_host: "dbhost".to_string(),
                postgres_port: 5432,
                postgres_user: "dbuser".to_string(),
                postgres_password: Some("dbsecret".to_string()),
                postgres_database: None,
                postgres_max_connections: 10,
            },
        };
        let summary = args.redacted_summary();
        // Assertions are value-based rather than pinned to clap's Debug rendering.
        // NetworkAddressWithPort renders the address and port as separate Debug fields,
        // so they are asserted separately.
        assert!(summary.contains("node_rpc_address"));
        assert!(summary.contains("127.0.0.1"));
        assert!(summary.contains("port: 12345"));
        assert!(summary.contains(REDACTED));
        assert!(summary.contains("node_rpc_cookie_file"));
        assert!(summary.contains("/tmp/rpc-cookie-file"));
        assert!(!summary.contains("alice"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("dbsecret"));
        let debug_dump = format!("{args:?}");
        assert!(debug_dump.contains("ApiServerScannerArgs"));
        assert!(debug_dump.contains(REDACTED));
        assert!(!debug_dump.contains("alice"));
        assert!(!debug_dump.contains("supersecret"));
        assert!(!debug_dump.contains("dbsecret"));
    }

    #[test]
    fn redacted_summary_renders_absent_secrets_as_none() {
        // Built directly so no ML_API_SCANNER_DAEMON_* environment fallback applies.
        let args = ApiServerScannerArgs {
            network: Network::Mainnet,
            node_rpc_address: None,
            node_rpc_cookie_file: None,
            node_rpc_username: None,
            node_rpc_password: None,
            postgres_config: PostgresConfig {
                postgres_host: "dbhost".to_string(),
                postgres_port: 5432,
                postgres_user: "dbuser".to_string(),
                postgres_password: None,
                postgres_database: None,
                postgres_max_connections: 10,
            },
        };
        let summary = args.redacted_summary();
        assert!(!summary.contains(REDACTED));
        assert!(summary.contains("node_rpc_username"));
        assert!(summary.contains("node_rpc_password"));
        assert!(summary.contains("postgres_password"));
    }
}
