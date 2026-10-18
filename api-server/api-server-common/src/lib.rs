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

/// Marker printed in place of a secret-bearing value that is not set.
pub const UNSET_SENTINEL: &str = "<unset>";

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

/// Returns a value-free ` for <flag>` suffix naming the rejected argument, or an
/// empty string when the error carries no invalid-argument context. The rejected
/// value lives in a separate clap context and is never included in the result.
fn offending_arg_suffix(err: &clap::Error) -> String {
    match err.get(clap::error::ContextKind::InvalidArg) {
        Some(clap::error::ContextValue::String(name)) if name.starts_with('-') => {
            // Only flag-shaped ids are echoed: for `UnknownArgument` raised on an
            // unexpected positional token, clap places the raw token itself (the
            // potential secret) into this same invalid-argument context.
            format!(" for {name}")
        }
        _ => String::new(),
    }
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
                    // The error kind's rendering is a static category name and the
                    // offending flag's id is value-free, so both are safe to include;
                    // the value context (e.g. the rejected input) never is.
                    let offending_arg = offending_arg_suffix(&err);
                    eprintln!(
                        "Invalid command line arguments ({:?}){offending_arg}; run with --help for usage",
                        err.kind()
                    );
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
    // `DisplayHelpOnMissingArgumentOrSubcommand` is deliberately excluded even though its
    // rendering is stderr-routed and value-free under the `hide_env_values` contract: a
    // binary configured with `arg_required_else_help` should print the generic message
    // rather than its full help when invoked with no arguments.
    matches!(
        kind,
        ErrorKind::ArgumentConflict
            | ErrorKind::MissingRequiredArgument
            | ErrorKind::MissingSubcommand
            | ErrorKind::NoEquals
    )
}

#[cfg(test)]
mod parse_args_tests {
    use super::offending_arg_suffix;
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

    #[test]
    fn offending_arg_suffix_names_the_flag_but_never_the_value() {
        let cmd = clap::Command::new("canary").arg(
            clap::Arg::new("postgres-port")
                .long("postgres-port")
                .value_parser(clap::value_parser!(usize)),
        );
        let err = cmd
            .try_get_matches_from(["canary", "--postgres-port", "99999999999999999999"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let suffix = offending_arg_suffix(&err);
        assert!(suffix.contains("postgres-port"), "{suffix}");
        assert!(!suffix.contains("99999999999999999999"), "{suffix}");
    }

    #[test]
    fn no_echo_kinds_never_carry_a_value_in_the_invalid_arg_context() {
        let secret = "s3cret-canary-value";
        // `InvalidValue` and `UnknownArgument` reach the generic no-echo message;
        // neither may smuggle the rejected value through the invalid-argument context.
        let cmd = clap::Command::new("canary")
            .arg(
                clap::Arg::new("rpc-password")
                    .long("rpc-password")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(clap::Arg::new("mode").long("mode").value_parser(["fast", "slow"]));

        let invalid_value =
            cmd.clone().try_get_matches_from(["canary", "--mode", secret]).unwrap_err();
        assert_eq!(invalid_value.kind(), clap::error::ErrorKind::InvalidValue);
        let suffix = offending_arg_suffix(&invalid_value);
        assert!(suffix.contains("mode"), "{suffix}");
        assert!(!suffix.contains(secret), "{suffix}");

        // Glue the value to the flag in one token: this is the form whose parse path
        // could plausibly copy the raw token into the invalid-arg context.
        let unknown = cmd
            .clone()
            .try_get_matches_from(["canary".to_owned(), format!("--unknown={secret}")])
            .unwrap_err();
        assert_eq!(unknown.kind(), clap::error::ErrorKind::UnknownArgument);
        let suffix = offending_arg_suffix(&unknown);
        assert!(!suffix.contains(secret), "{suffix}");

        // An unexpected bare positional token is also echoed into the invalid-arg
        // context by clap; the suffix must stay empty there.
        let bare = cmd.try_get_matches_from(["canary".to_owned(), secret.to_owned()]).unwrap_err();
        assert_eq!(bare.kind(), clap::error::ErrorKind::UnknownArgument);
        assert_eq!(offending_arg_suffix(&bare), "");
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

const DEFAULT_POSTGRES_HOST: &str = "localhost";
const DEFAULT_POSTGRES_PORT: u16 = 5432;
const DEFAULT_POSTGRES_USER: &str = "postgres";
const DEFAULT_POSTGRES_MAX_CONNECTIONS: u32 = 10;

// When adding a field, keep the Debug destructure, the `Default` impl, and the
// `default_matches_clap_defaults` test in sync, and classify the new option in the
// help-output guard tests of both daemons.
#[derive(Parser, PartialEq)]
pub struct PostgresConfig {
    /// Postgres host
    #[clap(long, default_value = DEFAULT_POSTGRES_HOST)]
    pub postgres_host: String,

    /// Postgres port
    #[clap(long, default_value_t = DEFAULT_POSTGRES_PORT)]
    pub postgres_port: u16,

    /// Postgres user
    #[clap(long, default_value = DEFAULT_POSTGRES_USER)]
    pub postgres_user: String,

    /// Postgres password
    #[clap(long)]
    pub postgres_password: Option<String>,

    /// Postgres database
    #[clap(long)]
    pub postgres_database: Option<String>,

    /// Postgres max connections
    #[clap(long, default_value_t = DEFAULT_POSTGRES_MAX_CONNECTIONS)]
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
        // Shared constants, not parsing: parsing here would read the process's real
        // arguments and is not safe outside of the actual CLI startup.
        Self {
            postgres_host: DEFAULT_POSTGRES_HOST.to_string(),
            postgres_port: DEFAULT_POSTGRES_PORT,
            postgres_user: DEFAULT_POSTGRES_USER.to_string(),
            postgres_password: None,
            postgres_database: None,
            postgres_max_connections: DEFAULT_POSTGRES_MAX_CONNECTIONS,
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
