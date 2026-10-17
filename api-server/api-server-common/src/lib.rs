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
/// secrets. Only errors whose clap rendering is guaranteed to name flags or static text
/// (ArgumentConflict, MissingRequiredArgument, MissingSubcommand, NoEquals, plus help
/// and version) are printed as-is; every other error, including UnknownArgument, is
/// replaced by a generic message.
///
/// # Contract with the argument definitions
///
/// Help and version output is echoed verbatim, and the error fallback tells users to
/// run `--help`. Any secret-bearing argument bound to an environment variable must
/// therefore set `hide_env_values(true)` (see
/// `clap_utils::env_adder_hiding_env_values`), otherwise clap renders
/// `[env: NAME=value]` into the help text and this function prints the secret.
pub fn parse_args_or_exit<T: clap::Parser>() -> T {
    match T::try_parse() {
        Ok(args) => args,
        Err(err) => {
            if err.use_stderr() {
                if error_is_value_free(err.kind()) {
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

/// Whether the clap rendering of this error kind is guaranteed to name flags or static
/// text only, never raw argument values.
fn error_is_value_free(kind: clap::error::ErrorKind) -> bool {
    use clap::error::ErrorKind;
    matches!(
        kind,
        ErrorKind::ArgumentConflict
            | ErrorKind::MissingRequiredArgument
            | ErrorKind::MissingSubcommand
            | ErrorKind::NoEquals // DisplayHelpOnMissingArgumentOrSubcommand (stderr-routed, value-free under the
                                  // hide_env_values contract) is deliberately excluded, so a binary configured
                                  // with `arg_required_else_help` prints the generic message rather than its help
                                  // on empty arguments.
    )
}

#[cfg(test)]
mod parse_args_tests {
    use clap::error::ErrorKind;

    #[test]
    fn value_bearing_error_kinds_are_suppressed() {
        assert!(!super::error_is_value_free(ErrorKind::InvalidValue));
        assert!(!super::error_is_value_free(ErrorKind::ValueValidation));
        assert!(!super::error_is_value_free(ErrorKind::UnknownArgument));
    }

    #[test]
    fn flag_naming_error_kinds_are_printed() {
        assert!(super::error_is_value_free(
            ErrorKind::MissingRequiredArgument
        ));
        assert!(super::error_is_value_free(ErrorKind::ArgumentConflict));
        assert!(super::error_is_value_free(ErrorKind::MissingSubcommand));
        assert!(super::error_is_value_free(ErrorKind::NoEquals));
    }

    /// Pins that the clap rendering of the allowlisted kinds never embeds raw argument
    /// values, so a clap upgrade that starts echoing them fails here instead of leaking
    /// secrets in production.
    #[test]
    fn allowlisted_kinds_never_render_raw_values() {
        let secret = "s3cret-canary-value";
        let cmd = clap::Command::new("canary")
            .arg(clap::Arg::new("a").long("a").num_args(1))
            .arg(
                clap::Arg::new("b")
                    .long("b")
                    .conflicts_with("a")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(clap::Arg::new("c").long("c").required(true));

        let conflict =
            cmd.clone().try_get_matches_from(["canary", "--a", secret, "--b"]).unwrap_err();
        assert_eq!(conflict.kind(), clap::error::ErrorKind::ArgumentConflict);
        assert!(!conflict.render().to_string().contains(secret));

        let missing_required =
            cmd.clone().try_get_matches_from(["canary", "--a", secret]).unwrap_err();
        assert_eq!(
            missing_required.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(!missing_required.render().to_string().contains(secret));

        let requires_equals = clap::Command::new("canary")
            .arg(clap::Arg::new("a").long("a").require_equals(true).num_args(1));
        let no_equals =
            requires_equals.try_get_matches_from(["canary", "--a", secret]).unwrap_err();
        assert_eq!(no_equals.kind(), clap::error::ErrorKind::NoEquals);
        assert!(!no_equals.render().to_string().contains(secret));

        let subcommanded = clap::Command::new("canary")
            .subcommand_required(true)
            .subcommand(clap::Command::new("run"));
        let missing_subcommand = subcommanded.try_get_matches_from(["canary"]).unwrap_err();
        assert_eq!(
            missing_subcommand.kind(),
            clap::error::ErrorKind::MissingSubcommand
        );
        assert!(!missing_subcommand.render().to_string().contains(secret));
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

#[derive(Parser, PartialEq)]
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
        // Literal defaults mirroring the clap `default_value` attributes above; parsing
        // here would read the process's real arguments and is not safe outside of the
        // actual CLI startup.
        Self {
            postgres_host: "localhost".to_string(),
            postgres_port: 5432,
            postgres_user: "postgres".to_string(),
            postgres_password: None,
            postgres_database: None,
            postgres_max_connections: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_clap_defaults() {
        let from_clap = PostgresConfig::parse_from(["postgres-config"]);
        assert_eq!(from_clap, PostgresConfig::default());
    }

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
