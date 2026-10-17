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

/// Marker printed in place of any secret-bearing value.
pub const REDACTED: &str = "<redacted>";

/// Debug-safe replacement for an `Option` that may hold a secret.
pub fn redact<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

/// A loggable summary of the options, omitting every value that can hold a secret.
/// Implementors must consciously provide the summary; for types whose hand-written Debug
/// impl redacts the secret-bearing fields (with an exhaustive destructure guarding new
/// fields), the body is the Debug output itself.
pub trait RedactedSummary: std::fmt::Debug {
    fn redacted_summary(&self) -> String;
}

/// Parses command line arguments, and on failure exits without echoing them: clap errors
/// for value-bearing arguments can repeat raw `--flag=value` tokens, which may carry
/// secrets. Errors that only name flags or render static text (missing arguments,
/// conflicts, help and version) are printed as-is.
pub fn parse_args_or_exit<T: clap::Parser>() -> T {
    use clap::error::ErrorKind;
    match T::try_parse() {
        Ok(args) => args,
        Err(err) => {
            let value_free = matches!(
                err.kind(),
                ErrorKind::ArgumentConflict
                    | ErrorKind::MissingRequiredArgument
                    | ErrorKind::MissingSubcommand
                    | ErrorKind::NoEquals
            );
            if err.use_stderr() {
                if value_free {
                    let _ = err.print();
                } else {
                    eprintln!("Invalid command line arguments; run with --help for usage");
                }
                std::process::exit(2);
            }
            let _ = err.print();
            std::process::exit(0);
        }
    }
}

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
// derived Debug (command line option dumps, error types) is safe by construction. The
// destructure has no `..` so a newly added field fails to compile until it is either added
// here or shown to be safe. The database role name in `postgres_user` is not a credential
// and is shown in clear text, unlike the RPC username, which is part of the basic-auth
// credential pair.
impl std::fmt::Debug for PostgresConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            postgres_host,
            postgres_port,
            postgres_user,
            postgres_password,
            postgres_database,
            postgres_max_connections,
        } = self;
        f.debug_struct("PostgresConfig")
            .field("postgres_host", postgres_host)
            .field("postgres_port", postgres_port)
            .field("postgres_user", postgres_user)
            .field("postgres_password", &redact(postgres_password))
            .field("postgres_database", postgres_database)
            .field("postgres_max_connections", postgres_max_connections)
            .finish()
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        // Route through the non-echoing parse path.
        parse_args_or_exit::<PostgresConfig>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_postgres_password() {
        let config = PostgresConfig::parse_from([
            "postgres-config",
            "--postgres-host",
            "dbhost",
            "--postgres-password",
            "dbsecret",
        ]);
        let dump = format!("{config:?}");
        assert!(dump.contains("postgres_host: \"dbhost\""));
        assert!(dump.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!dump.contains("dbsecret"));
    }
}
