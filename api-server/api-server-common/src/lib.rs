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

pub mod storage;
pub mod streaming;

use clap::Parser;
use common::chain::config::ChainType;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

#[derive(Parser)]
pub struct PostgresConfig {
    /// Postgres host
    #[clap(long, default_value = "localhost")]
    pub postgres_host: String,

    /// Postgres port
    #[clap(long, default_value = "5432")]
    pub postgres_port: u16,

    /// Postgres user
    #[clap(long, default_value = "postgres")]
    pub postgres_user: String,

    /// Postgres password
    #[clap(long)]
    pub postgres_password: Option<String>,

    /// Postgres database
    #[clap(long)]
    pub postgres_database: Option<String>,

    /// Postgres max connections
    #[clap(long, default_value = "10")]
    pub postgres_max_connections: u32,
}

// The password must never appear in debug output; anything that embeds this struct in a
// derived Debug (command line option dumps, error types) is safe by construction.
impl std::fmt::Debug for PostgresConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresConfig")
            .field("postgres_host", &self.postgres_host)
            .field("postgres_port", &self.postgres_port)
            .field("postgres_user", &self.postgres_user)
            .field(
                "postgres_password",
                &self.postgres_password.as_ref().map(|_| "<redacted>"),
            )
            .field("postgres_database", &self.postgres_database)
            .field("postgres_max_connections", &self.postgres_max_connections)
            .finish()
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_postgres_password() {
        let config = PostgresConfig::parse_from(["postgres-config", "--postgres-password", "dbsecret"]);
        let dump = format!("{config:?}");
        assert!(dump.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!dump.contains("dbsecret"));
    }
}
