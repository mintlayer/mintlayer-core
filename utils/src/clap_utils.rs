// Copyright (c) 2021-2024 RBB S.r.l
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

use clap::Arg;
use heck::ToShoutySnakeCase;

/// This function can be used with clap's `mut_args` to add the "env" attribute
/// to each field of a struct that derives `clap::Parser`.
///
/// The name of the environment variable will be based on the "long" name of the argument;
/// if the argument has no long name, "env" won't be set. E.g.
/// ```
/// # use utils::clap_utils::add_env;
/// #[derive(clap::Parser)]
/// #[clap(mut_args(|arg| add_env("FOO", arg)))]
/// pub struct MyOptions {
///     #[arg(long)]
///     pub the_option_name: String,
/// }
/// ```
/// In this example, the env var name will be `ML_FOO_THE_OPTION_NAME`.
///
/// By convention, the infix ("FOO" in the example above) is supposed to uniquely identify
/// the executable for which the arguments are being defined.
pub fn add_env(infix: &str, mut arg: Arg) -> Arg {
    if let Some(long_name) = arg.get_long() {
        let var_name = format!("ML_{}_{}", infix, long_name.to_shouty_snake_case());
        arg = arg.env(var_name);
    }

    arg
}

/// A convenience function to make the corresponding calls to `mut_args` less noisy.
pub fn env_adder(infix: &str) -> impl FnMut(Arg) -> Arg + '_ {
    |arg| add_env(infix, arg)
}

/// Same as [`env_adder`], but the values of the options named in `hidden` are excluded
/// from the help output, so secrets provided through the environment are not rendered
/// as `[env: NAME=value]`.
///
/// Matching is by exact long name: an option missing from (or misspelled in) `hidden`
/// silently keeps rendering its environment value in `--help`. Always pair this helper
/// with [`assert_secret_options_hidden`] in a test so the list is pinned against the
/// derived command.
pub fn env_adder_hiding_env_values<'a>(
    infix: &'a str,
    hidden: &'a [&'a str],
) -> impl FnMut(Arg) -> Arg + 'a {
    move |mut arg| {
        arg = add_env(infix, arg);
        if arg.get_long().is_some_and(|long| hidden.contains(&long)) {
            arg = arg.hide_env_values(true);
        }
        arg
    }
}

/// Test helper: asserts that every option named in `secret_options` exists in `cmd`
/// (recursively, including all nested subcommands), is bound to an environment variable,
/// and has its environment-sourced value hidden from the help output.
// Gated additionally on `test-util` so consumer test suites can reach it through a
// dev-dependency feature entry, while this crate's own test units get it from plain
// `cfg(test)`.
#[cfg(any(test, feature = "test-util"))]
fn collect_args<'a>(cmd: &'a clap::Command, args: &mut Vec<&'a clap::Arg>) {
    args.extend(cmd.get_arguments());
    for sub in cmd.get_subcommands() {
        collect_args(sub, args);
    }
}

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn assert_secret_options_hidden(cmd: &clap::Command, secret_options: &[&str]) {
    let mut all_args = Vec::new();
    collect_args(cmd, &mut all_args);
    let secrets = secret_options.iter().copied().collect::<std::collections::HashSet<_>>();
    let mut matched = std::collections::HashSet::new();
    for arg in all_args {
        if let Some(long) = arg.get_long().filter(|long| secrets.contains(long)) {
            assert!(
                arg.is_hide_env_values_set(),
                "env value of --{long} is not hidden from help"
            );
            assert!(
                arg.get_env().is_some(),
                "--{long} has no environment variable bound; env wiring was dropped"
            );
            matched.insert(long);
        }
    }
    let mut matched: Vec<_> = matched.into_iter().collect();
    let mut expected: Vec<_> = secret_options.to_vec();
    matched.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        matched, expected,
        "the secret options list does not match the actual secret options; \
         stale entries pass silently and missing entries leak env values in --help"
    );
}

/// Test helper: same as [`assert_secret_options_hidden`], plus an exhaustive
/// classification check: every option of `cmd` must be listed in `secret_options` or
/// `non_secret_options`, and every non-secret entry must exist in the command.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn assert_options_classified(
    cmd: &clap::Command,
    secret_options: &[&str],
    non_secret_options: &[&str],
) {
    assert_secret_options_hidden(cmd, secret_options);
    let mut all_args = Vec::new();
    collect_args(cmd, &mut all_args);
    let longs: std::collections::HashSet<_> =
        all_args.iter().filter_map(|arg| arg.get_long()).collect();
    let unclassified: Vec<_> = longs
        .iter()
        .copied()
        .filter(|long| !secret_options.contains(long) && !non_secret_options.contains(long))
        .collect();
    assert!(
        unclassified.is_empty(),
        "options not classified as secret or non-secret: {unclassified:?}"
    );
    let stale: Vec<_> = non_secret_options
        .iter()
        .copied()
        .filter(|long| !longs.contains(long))
        .collect();
    assert!(
        stale.is_empty(),
        "non-secret options not found in the command (stale entries): {stale:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_values_are_hidden_only_for_the_named_options() {
        let mut wrap = env_adder_hiding_env_values("NODE", &["rpc-username", "rpc-password"]);

        let arg = wrap(clap::Arg::new("rpc_password").long("rpc-password"));
        assert!(arg.is_hide_env_values_set());
        assert!(arg.get_env().is_some());

        let arg = wrap(clap::Arg::new("rpc_username").long("rpc-username"));
        assert!(arg.is_hide_env_values_set());
        assert!(arg.get_env().is_some());

        let arg = wrap(clap::Arg::new("datadir").long("datadir"));
        assert!(!arg.is_hide_env_values_set());
        assert!(arg.get_env().is_some());
    }
}

// The helper carries the `test-util` gate (see its definition); these tests exercise it
// in this crate's own test units, which get it from plain `cfg(test)`.
#[cfg(test)]
mod secret_options_guard_tests {
    use super::*;

    #[test]
    fn guard_accepts_a_wired_command_tree() {
        let cmd = clap::Command::new("root").subcommand(
            clap::Command::new("sub").arg(
                add_env("NODE", clap::Arg::new("rpc_password").long("rpc-password"))
                    .hide_env_values(true),
            ),
        );
        assert_secret_options_hidden(&cmd, &["rpc-password"]);
    }

    #[test]
    #[should_panic(expected = "does not match the actual secret options")]
    fn guard_rejects_a_stale_entry() {
        let cmd = clap::Command::new("root").arg(
            add_env("NODE", clap::Arg::new("rpc_password").long("rpc-password"))
                .hide_env_values(true),
        );
        assert_secret_options_hidden(&cmd, &["rpc-password", "old-option"]);
    }

    #[test]
    #[should_panic(expected = "does not match the actual secret options")]
    fn guard_rejects_a_missing_entry() {
        let cmd = clap::Command::new("root")
            .arg(add_env("NODE", clap::Arg::new("datadir").long("datadir")));
        assert_secret_options_hidden(&cmd, &["rpc-password"]);
    }

    #[test]
    #[should_panic(expected = "not hidden from help")]
    fn guard_rejects_an_unhidden_option() {
        let cmd = clap::Command::new("root").arg(
            add_env("NODE", clap::Arg::new("rpc_password").long("rpc-password"))
                // The env wiring is present but the value is not hidden.
                .hide_env_values(false),
        );
        assert_secret_options_hidden(&cmd, &["rpc-password"]);
    }

    #[test]
    #[should_panic(expected = "no environment variable bound")]
    fn guard_rejects_a_dropped_env_binding() {
        let cmd = clap::Command::new("root")
            .arg(clap::Arg::new("rpc_password").long("rpc-password").hide_env_values(true));
        assert_secret_options_hidden(&cmd, &["rpc-password"]);
    }

    #[test]
    #[should_panic(expected = "not classified as secret or non-secret")]
    fn classification_rejects_an_unclassified_option() {
        let cmd = clap::Command::new("root")
            .arg(add_env("NODE", clap::Arg::new("datadir").long("datadir")));
        assert_options_classified(&cmd, &[], &[]);
    }

    #[test]
    #[should_panic(expected = "stale entries")]
    fn classification_rejects_a_stale_non_secret_entry() {
        let cmd = clap::Command::new("root")
            .arg(add_env("NODE", clap::Arg::new("datadir").long("datadir")));
        assert_options_classified(&cmd, &[], &["datadir", "old-option"]);
    }
}
