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

use std::collections::BTreeSet;

use std::sync::Arc;

use clap::{Arg, ArgAction, Command};
use reedline::{Completer, Hinter, Span, Suggestion};
use wallet_cli_commands::{expands_first_level, first_about_line, visible_first_level_subcommands};

/// A completer that walks the clap command tree, offering subcommand names,
/// long flags, and enumeration values for the token in front of the cursor.
#[derive(Clone)]
pub struct WalletCompletions {
    root: Arc<Command>,
    /// When true (the ghost-hint channel), the leaf flag fallback is
    /// suppressed: a dimmed hint trailing the cursor with `--mnemonic` after
    /// a free-form token would read as an extension of the user's own input.
    /// The TAB menu keeps the fallback.
    hint_mode: bool,
}

impl WalletCompletions {
    /// Share the grammar.
    ///
    /// [`Command::build`] runs only when the caller passes an owned
    /// [`Command`] or an unshared [`std::sync::Arc`]; callers sharing an
    /// already-wrapped [`std::sync::Arc`] must pass a built tree (as
    /// `build_repl_command` does).
    pub fn new(root: impl Into<Arc<Command>>) -> Self {
        let mut root = root.into();
        if let Some(root) = Arc::get_mut(&mut root) {
            root.build();
        } else {
            // A shared command cannot be built here; callers holding a shared
            // Arc must pass an already-built tree (as `build_repl_command`
            // does). Walking an unbuilt tree silently yields no candidates.
            // `build()` is what injects the help flag, so its presence is the
            // cheapest proxy for "this tree was built".
            if !root.get_arguments().any(|arg| arg.get_long() == Some("help")) {
                debug_assert!(false, "a shared clap Command must already be built");
                // The assertion above is compiled out in release builds, so also
                // leave a trace: the completer will produce no candidates.
                logging::log::warn!(
                    "WalletCompletions received an unbuilt clap command tree; completions will be empty"
                );
            }
        }
        Self {
            root,
            hint_mode: false,
        }
    }

    /// Takes an already-built grammar and trusts the caller: use this where
    /// the [`Command`] is shared behind an [`std::sync::Arc`] and the builder
    /// contract is known to hold (as with `build_repl_command` output).
    pub fn from_built(root: Arc<Command>) -> Self {
        Self {
            root,
            hint_mode: false,
        }
    }

    /// Switch the completer into ghost-hint mode: the leaf flag fallback is
    /// suppressed so the dimmed hint never trails the cursor with flags
    /// after a free-form token. The TAB menu keeps the fallback.
    pub fn set_hint_mode(&mut self, hint_mode: bool) {
        self.hint_mode = hint_mode;
    }

    /// A completer without any candidates, used where completion is not
    /// meaningful (for example the choice menu).
    pub fn empty() -> Self {
        Self::new(Command::new("empty").disable_help_flag(true).disable_help_subcommand(true))
    }
}

/// One candidate token with its help description.
struct Candidate {
    value: String,
    description: Option<String>,
}

fn flag_candidates(cmd: &Command, taken: &BTreeSet<String>) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for arg in cmd.get_arguments() {
        let Some(long) = arg.get_long() else {
            continue;
        };
        if arg.is_hide_set() {
            continue;
        }
        let repeatable = matches!(arg.get_action(), ArgAction::Append);
        if !repeatable && taken.contains(long) {
            continue;
        }
        let mut description =
            arg.get_long_help().or_else(|| arg.get_help()).map(|help| help.to_string());
        if arg.get_num_args().is_some_and(|range| range.takes_values()) {
            let value_name = match arg.get_value_names() {
                Some(names) => {
                    names.iter().map(|name| name.to_string()).collect::<Vec<_>>().join(" ")
                }
                None => "value".to_owned(),
            };
            description = Some(match description {
                Some(help) => format!("{help} <{value_name}>"),
                None => format!("<{value_name}>"),
            });
        }
        candidates.push(Candidate {
            value: format!("--{long}"),
            description,
        });
    }
    candidates
}

fn subcommand_candidates(cmd: &Command) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        // `build_repl_command` appends a trailing EOL to each top-level
        // command's `about` for help formatting; trim it so completion menu
        // entries do not carry a stray newline.
        let description = sub.get_about().map(|about| about.to_string().trim().to_owned());
        candidates.push(Candidate {
            value: sub.get_name().to_owned(),
            description: description.clone(),
        });
        for alias in sub.get_visible_aliases() {
            candidates.push(Candidate {
                value: alias.to_owned(),
                description: description.clone(),
            });
        }
    }
    candidates
}

/// Candidates for the positional argument at `index` (zero based) of `cmd`,
/// given the token the user is completing (`typed`).
///
/// `index` counts ALL positionals, hidden ones included: clap assigns tokens
/// to positionals in declaration order regardless of hiding, and
/// `resolve_level` counts tokens the same way. A hidden positional's values
/// stay out of the advertised menu (a bare TAB yields nothing), but input
/// that already prefix-matches one of them is finished, so the legacy compat
/// spellings remain completable.
fn positional_candidates(cmd: &Command, index: usize, typed: &str) -> Vec<Candidate> {
    let positionals: Vec<&Arg> = cmd.get_arguments().filter(|arg| arg.is_positional()).collect();
    let arg = positionals.get(index).copied().or_else(|| {
        positionals
            .last()
            .copied()
            .filter(|last| !last.is_hide_set() && matches!(last.get_action(), ArgAction::Append))
    });
    let Some(arg) = arg else {
        return Vec::new();
    };
    if arg.is_hide_set() {
        // A hidden positional's values stay out of the advertised menu; input
        // of at least two characters that already prefix-matches one of them
        // (the legacy compat spellings) is finished — completion on prefix is
        // not advertisement, but a single keystroke would effectively be one.
        if typed.chars().count() < 2 {
            return Vec::new();
        }
        return possible_value_candidates(arg.get_possible_values())
            .into_iter()
            .filter(|candidate| candidate.value.starts_with(typed))
            .collect();
    }
    possible_value_candidates(arg.get_possible_values())
}

/// Candidates spelled as two tokens (`transaction inspect`), offered at the
/// root so the completion menu mirrors the `help full` listing. Hidden
/// commands (the legacy flat spellings) are kept out of it.
fn first_level_path_candidates(cmd: &Command) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for group in cmd.get_subcommands() {
        if group.is_hide_set() {
            continue;
        }
        let group_name = group.get_name();
        if !expands_first_level(group) {
            continue;
        }
        for sub in visible_first_level_subcommands(group) {
            candidates.push(Candidate {
                value: format!("{group_name} {}", sub.get_name()),
                // The same first-line rule `help full` uses, so the menu and
                // the listing describe a command identically.
                description: Some(first_about_line(sub)).filter(|line| !line.is_empty()),
            });
        }
    }
    candidates
}

fn value_candidates(pending_value_flag: Option<&Arg>) -> Vec<Candidate> {
    let Some(arg) = pending_value_flag else {
        return Vec::new();
    };
    possible_value_candidates(arg.get_possible_values())
}

fn possible_value_candidates(values: Vec<clap::builder::PossibleValue>) -> Vec<Candidate> {
    values
        .into_iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| Candidate {
            value: value.get_name().to_owned(),
            description: value.get_help().map(|help| help.to_string()),
        })
        .collect()
}

/// Walk the tokenized prefix of the line and return the command level the
/// cursor sits at, the long flags already given at that level, the number of
/// positional values consumed, and a flag whose value is still missing.
///
/// The walk assumes the grammar has no lone `--` separator and no values that
/// start with a hyphen; the wallet grammar has neither.
struct Level<'a> {
    cmd: &'a Command,
    taken_flags: BTreeSet<String>,
    positional_index: usize,
    pending_value_flag: Option<&'a Arg>,
    /// True once the walk descended through a `help` subcommand (root or
    /// group-level): everything under it is a help topic, not a command.
    through_help: bool,
}

fn resolve_level<'a>(root: &'a Command, tokens: &[&str]) -> Level<'a> {
    let mut cmd = root;
    let mut taken_flags = BTreeSet::new();
    let mut positional_index = 0usize;
    let mut pending_value_flag: Option<&'a Arg> = None;
    let mut through_help = false;
    for token in tokens {
        if let Some(stripped) = token.strip_prefix("--") {
            pending_value_flag = None;
            let (long, inline_value) = match stripped.split_once('=') {
                Some((long, _)) => (long, true),
                None => (stripped, false),
            };
            if let Some(arg) = cmd.get_arguments().find(|arg| arg.get_long() == Some(long)) {
                let repeatable = matches!(arg.get_action(), ArgAction::Append);
                if !repeatable {
                    taken_flags.insert(long.to_owned());
                }
                let takes_value = arg.get_num_args().is_some_and(|range| range.takes_values());
                if takes_value && !inline_value {
                    // The flag still awaits its value; remember it in case the
                    // next token is being completed.
                    pending_value_flag = Some(arg);
                }
            }
            continue;
        }
        if token.len() > 1 && token.starts_with('-') {
            // A short flag (such as the automatic -h) is never a positional.
            pending_value_flag = None;
            let short = token.chars().nth(1);
            if let Some(arg) = cmd
                .get_arguments()
                .find(|arg| arg.get_short().is_some_and(|s| Some(s) == short))
            {
                let repeatable = matches!(arg.get_action(), ArgAction::Append);
                if !repeatable && let Some(long) = arg.get_long() {
                    taken_flags.insert(long.to_owned());
                }
                let takes_value = arg.get_num_args().is_some_and(|range| range.takes_values());
                let value_attached = token.chars().count() > 2;
                if takes_value && !value_attached {
                    pending_value_flag = Some(arg);
                }
            }
            continue;
        }
        // Not a flag: the value of the preceding flag, a subcommand, or a
        // positional value, in that order.
        if pending_value_flag.take().is_some() {
            continue;
        }
        // Hidden subcommands are still accepted by clap, so resolve them when
        // typed; `subcommand_candidates` keeps them out of the offered menu.
        if let Some(sub) = cmd.find_subcommand(token) {
            if sub.get_name() == "help" {
                through_help = true;
            }
            cmd = sub;
            taken_flags.clear();
            positional_index = 0;
            pending_value_flag = None;
            continue;
        }
        positional_index += 1;
    }
    Level {
        cmd,
        taken_flags,
        positional_index,
        pending_value_flag,
        through_help,
    }
}

impl Completer for WalletCompletions {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let Some(prefix) = line.get(..pos) else {
            return Vec::new();
        };
        let ends_with_space = prefix.ends_with(char::is_whitespace);
        let tokens: Vec<&str> = prefix.split_whitespace().collect();
        let (tokens, current): (Vec<&str>, &str) = if ends_with_space || tokens.is_empty() {
            (tokens, "")
        } else {
            (
                tokens[..tokens.len() - 1].to_vec(),
                tokens[tokens.len() - 1],
            )
        };

        let level = resolve_level(&self.root, &tokens);
        // A flag whose value is being typed after `=` completes that flag's
        // values instead of flag names.
        let inline_value_flag =
            current.strip_prefix("--").and_then(|rest| rest.split_once('=')).and_then(
                |(flag, _)| level.cmd.get_arguments().find(|arg| arg.get_long() == Some(flag)),
            );
        let mut candidates = if let Some(arg) = inline_value_flag {
            value_candidates(Some(arg))
        } else if let Some(arg) = level.pending_value_flag {
            // clap would consume any `--`-prefixed token as this flag's value
            // (and reject it), so complete the flag's values instead of
            // offering flag names.
            value_candidates(Some(arg))
        } else if current.starts_with("--") {
            flag_candidates(level.cmd, &level.taken_flags)
        } else {
            let mut candidates = subcommand_candidates(level.cmd);
            // At the root, the completion menu mirrors the `help full`
            // listing: the primary commands plus every first-level
            // subcommand spelled as its full two-token path. The two
            // advertised help views stay completable as well.
            if std::ptr::eq(level.cmd, &*self.root) {
                candidates.extend(first_level_path_candidates(level.cmd));
                if self.root.find_subcommand("legacy").is_some() {
                    candidates.push(Candidate {
                        value: "help full".to_owned(),
                        description: Some(
                            "List every command with its first-level subcommands".to_owned(),
                        ),
                    });
                    candidates.push(Candidate {
                        value: "legacy".to_owned(),
                        description: Some(
                            "List the legacy flat command spellings with their nested equivalents"
                                .to_owned(),
                        ),
                    });
                }
            } else if self
                .root
                .find_subcommand("help")
                .is_some_and(|root_help| std::ptr::eq(level.cmd, root_help))
                && self.root.find_subcommand("legacy").is_some()
            {
                // Under the root's auto `help` command, clap mirrors the
                // top-level commands but not the `full` view; offer it so the
                // advertised `help full` syntax completes. Every group gets
                // its own auto `help` too, where `help full` does not parse,
                // so the pointer identity above scopes the offer to the root.
                candidates.push(Candidate {
                    value: "full".to_owned(),
                    description: Some(
                        "List every command with its first-level subcommands".to_owned(),
                    ),
                });
            }
            let positional_values =
                positional_candidates(level.cmd, level.positional_index, current);
            // A leaf command's positional slot with no enumeration (a path,
            // an address, a hex blob) offers nothing on its own; surface the
            // command's flags instead, so the next step stays discoverable.
            // Levels with subcommands keep offering those instead.
            // Under any `help` command (root or group-level), the mirrored
            // leaves are help topics, not commands: the fallback is
            // suppressed there. The ghost-hint channel suppresses it too.
            let at_leaf = level.cmd.get_subcommands().next().is_none();
            if at_leaf && !self.hint_mode && !level.through_help && positional_values.is_empty() {
                // The auto-added --help is not offered here: an exhausted
                // command keeps its menu clean (it stays completable when the
                // user explicitly types "--").
                candidates.extend(
                    flag_candidates(level.cmd, &level.taken_flags)
                        .into_iter()
                        .filter(|candidate| candidate.value != "--help"),
                );
            }
            candidates.extend(positional_values);
            candidates
        };

        // Keep the menu alphabetical, matching the grammar's help ordering.
        candidates.sort_by(|lhs, rhs| lhs.value.cmp(&rhs.value));

        // For the inline `--flag=<typed>` form, match and replace only the
        // typed part after `=`; otherwise match and replace the whole token.
        let (match_prefix, typed_len): (&str, usize) = if inline_value_flag.is_some() {
            let value_part = current.split_once('=').map_or("", |(_, value)| value);
            (value_part, value_part.len())
        } else {
            (current, current.len())
        };
        let start = pos.saturating_sub(typed_len);
        candidates
            .into_iter()
            .filter(|candidate| candidate.value.starts_with(match_prefix))
            .map(|candidate| Suggestion {
                value: candidate.value,
                description: candidate.description,
                extra: None,
                span: Span::new(start, pos),
                append_whitespace: false,
                style: None,
            })
            .collect()
    }
}

/// Ghost-text hints built on top of [`WalletCompletions`]: the first matching
/// completion is shown dimmed after the cursor.
pub struct WalletHinter {
    completer: WalletCompletions,
    current_hint: String,
    last_input: Option<(String, usize)>,
}

impl WalletHinter {
    pub fn new(completer: WalletCompletions) -> Self {
        // The ghost-hint channel suppresses the leaf flag fallback: a dimmed
        // hint trailing the cursor with `--mnemonic` after a free-form path
        // token would read as an extension of the user's own input.
        let mut completer = completer;
        completer.set_hint_mode(true);
        Self {
            completer,
            current_hint: String::new(),
            last_input: None,
        }
    }
}

impl Hinter for WalletHinter {
    fn handle(
        &mut self,
        line: &str,
        pos: usize,
        _history: &dyn reedline::History,
        use_ansi_coloring: bool,
        _cwd: &str,
    ) -> String {
        // The completion walk is pure, so repeat calls with the same input can
        // reuse the previous result instead of re-walking the grammar.
        if self
            .last_input
            .as_ref()
            .is_none_or(|(last_line, last_pos)| last_line != line || *last_pos != pos)
        {
            self.last_input = Some((line.to_owned(), pos));
            self.current_hint = self
                .completer
                .complete(line, pos)
                .first()
                .map(|suggestion| {
                    let typed = pos.saturating_sub(suggestion.span.start);
                    suggestion.value.get(typed..).unwrap_or_default().to_owned()
                })
                .unwrap_or_default();
        }
        if use_ansi_coloring && !self.current_hint.is_empty() {
            format!("\x1b[2m{}\x1b[0m", self.current_hint)
        } else {
            self.current_hint.clone()
        }
    }

    fn complete_hint(&self) -> String {
        self.current_hint.clone()
    }

    fn next_hint_token(&self) -> String {
        self.current_hint.split_whitespace().next().unwrap_or_default().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use reedline::History;
    use rstest::rstest;
    use wallet_cli_commands::{build_repl_command, full_command_listing};

    /// A small grammar with the shapes the completer must understand.
    #[derive(Parser, Debug)]
    #[clap(name = "test")]
    enum TestCommand {
        /// Send an amount
        Send {
            /// Destination address
            address: String,
        },
        /// Set the broadcast behavior
        Broadcast {
            /// Whether to broadcast
            #[clap(long = "broadcast")]
            broadcast: YesNo,
        },
        /// Group of commands
        Group {
            #[clap(subcommand)]
            command: GroupSubCommand,
        },
        /// Internal maintenance command
        #[clap(hide = true)]
        Sweep {
            /// Whether to sweep
            broadcast: YesNo,
        },
        /// Hidden maintenance group
        #[clap(hide = true, name = "purge")]
        Purge {
            #[command(subcommand)]
            command: PurgeSubCommand,
        },
    }

    #[derive(clap::Subcommand, Debug)]
    enum PurgeSubCommand {
        /// Purge everything
        All,
        /// Purge a range
        Range {
            /// Upper bound
            bound: u32,
        },
    }

    #[derive(clap::Subcommand, Debug)]
    enum GroupSubCommand {
        /// Show the status
        Status {
            /// Restrict the output
            kind: Kind,
        },
    }

    #[derive(clap::ValueEnum, Clone, Debug)]
    enum YesNo {
        Yes,
        No,
    }

    #[derive(clap::ValueEnum, Clone, Debug)]
    enum Kind {
        /// Everything
        Full,
        /// A short summary
        Short,
    }

    fn completer() -> WalletCompletions {
        WalletCompletions::new(TestCommand::command())
    }

    fn values(suggestions: &[Suggestion]) -> Vec<&str> {
        suggestions.iter().map(|suggestion| suggestion.value.as_str()).collect()
    }

    #[test]
    fn empty_line_offers_top_level_commands() {
        let mut completer = completer();
        let suggestions = completer.complete("", 0);
        let values = values(&suggestions);
        // The root menu mirrors the `help full` listing: the top-level
        // commands plus every first-level subcommand as a full path.
        assert_eq!(
            values,
            vec!["broadcast", "group", "group status", "help", "send"]
        );
    }

    #[test]
    fn hidden_commands_stay_out_of_the_root_menu_paths() {
        let mut completer = completer();
        // The hidden `sweep` command is not offered directly...
        let suggestions = completer.complete("", 0);
        let offered = values(&suggestions);
        assert!(!offered.contains(&"sweep"));
        // ...and there is no group under it whose paths could leak in.

        // A hidden group with visible children must leak neither the group
        // name nor any two-token path into the root menu.
        assert!(!offered.contains(&"purge"));
        assert!(!offered.contains(&"purge all"));
        assert!(!offered.contains(&"purge range"));
        // Typing it still resolves: hidden commands stay runnable.
        let suggestions = completer.complete("purge ", 6);
        assert_eq!(values(&suggestions), vec!["all", "help", "range"]);
    }

    #[rstest]
    fn root_menu_matches_the_help_full_listing(
        #[values((false, true), (true, false), (true, true))] (cold_wallet, mutable_wallet): (
            bool,
            bool,
        ),
    ) {
        let grammar = wallet_cli_commands::run_with_large_stack(move || {
            build_repl_command(cold_wallet, mutable_wallet)
        });
        let mut completer = WalletCompletions::new(grammar.clone());

        let offered: std::collections::BTreeSet<String> =
            values(&completer.complete("", 0)).into_iter().map(str::to_owned).collect();

        let listing = full_command_listing(&grammar);
        let mut listed = std::collections::BTreeSet::new();
        for line in listing.lines().skip(1) {
            let token = line.trim_start().split("  ").next().expect("listing line with a token");
            listed.insert(token.to_owned());
            assert!(
                offered.contains(token),
                "the completion menu is missing the listed command `{token}`"
            );
        }
        // Everything offered is part of the listing or a visible alias of a
        // listed command (aliases stay usable in the menu), or one of the two
        // advertised help views the menu keeps completable.
        let mut aliases = std::collections::BTreeSet::new();
        for primary in grammar.get_subcommands().filter(|primary| !primary.is_hide_set()) {
            for alias in primary.get_visible_aliases() {
                aliases.insert(alias.to_owned());
            }
        }
        for value in &offered {
            assert!(
                listed.contains(value)
                    || aliases.contains(value)
                    || value == "help full"
                    || value == "legacy",
                "the completion menu offers `{value}`, which the full listing does not"
            );
        }

        // The legacy flat spellings that each grammar hides stay out of both
        // views; the ones a grammar keeps as primary spellings (cold wallets)
        // legitimately appear in both.
        let hidden_legacy: Vec<&str> = if cold_wallet {
            vec!["challenge-sign-plain", "history-print", "screen-clear"]
        } else {
            vec!["address-new", "wallet-create", "staking-create-pool"]
        };
        for legacy in hidden_legacy {
            assert!(
                !listed.contains(legacy),
                "the full listing shows `{legacy}`"
            );
            assert!(
                !offered.contains(legacy),
                "the completion menu shows `{legacy}`"
            );
        }
    }

    #[test]
    fn nested_subcommands_are_offered_after_the_group() {
        let mut completer = completer();
        let suggestions = completer.complete("group ", 6);
        assert_eq!(values(&suggestions), vec!["help", "status"]);
    }

    #[test]
    fn enumerated_leaf_keeps_its_values_without_the_flag_fallback() {
        let mut completer = completer();
        // A leaf whose positional slot enumerates (`group status` -> full |
        // short) keeps offering exactly those values; the flag fallback (which
        // would surface --help) must not fire.
        let suggestions = completer.complete("group status ", 13);
        assert_eq!(values(&suggestions), vec!["full", "short"]);
    }

    #[test]
    fn exhausted_enumerated_slot_gets_the_flag_fallback() {
        let mut completer = completer();
        // After an enumerated slot is consumed, previously-empty menus now
        // surface the command's flags (minus --help, which the fallback
        // filters).
        let suggestions = completer.complete("group status full ", 18);
        let offered = values(&suggestions);
        assert!(
            !offered.contains(&"full") && !offered.contains(&"short"),
            "the consumed slot's values must not be re-offered\n{offered:?}"
        );
        assert!(
            !offered.contains(&"--help"),
            "the fallback menu must not offer --help\n{offered:?}"
        );
    }

    #[test]
    fn non_leaf_levels_never_get_the_flag_fallback() {
        let mut completer = completer();
        // Subcommand levels keep offering subcommands only, even when their
        // slot is otherwise empty.
        let suggestions = completer.complete("group ", 6);
        assert_eq!(values(&suggestions), vec!["help", "status"]);
    }

    #[test]
    fn recover_variant_completes_the_storage_flag_values() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        let flag_value_suggestions =
            completer.complete("wallet recover software p --store-seed-phrase ", 46);
        assert_eq!(
            values(&flag_value_suggestions),
            vec!["false", "true"],
            "the recover variant must complete the storage flag values"
        );
    }

    #[test]
    fn help_topic_levels_never_get_the_flag_fallback() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        // Under the root help topics, leaves mirror the tree but have no
        // args; the fallback must not advertise flags there (inserting them
        // would make `help` fail to parse).
        let suggestions = completer.complete("help wallet create software ", 28);
        assert!(
            values(&suggestions).is_empty(),
            "help topic leaves must not receive the flag fallback"
        );
    }

    #[test]
    fn hinter_on_real_grammar_suppresses_fallback_flags() {
        // Pin the production wiring: WalletHinter::new sets hint mode on its
        // completer clone, so the ghost hint after a path token stays empty
        // even though the TAB menu offers fallback flags.
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut hinter = WalletHinter::new(WalletCompletions::new(grammar));
        let hint = hinter.handle(
            "wallet create software p ",
            25,
            &reedline::FileBackedHistory::default(),
            false,
            "",
        );
        assert!(
            hint.is_empty() || !hint.contains("--mnemonic"),
            "the ghost hint must not trail fallback flags\n{hint}"
        );
    }

    #[test]
    fn explicit_double_dash_still_offers_help() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        // The documented escape hatch: explicitly typing `--` at a leaf still
        // offers --help (it is only filtered from the fallback menus).
        let suggestions = completer.complete("send --", 7);
        assert!(
            values(&suggestions).contains(&"--help"),
            "explicit `--` must still offer --help"
        );
    }

    #[test]
    fn group_level_help_topics_never_get_the_flag_fallback() {
        // Group-level auto help (e.g. `wallet help create software `) mirrors
        // the tree the same way the root help does: its leaves have no flags,
        // so the fallback must stay suppressed there too.
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        let suggestions = completer.complete("wallet help create software ", 29);
        assert!(
            values(&suggestions).is_empty(),
            "group-level help topics must not receive the flag fallback"
        );
    }

    #[test]
    fn inline_equals_form_completes_flag_values() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        let suggestions = completer.complete("wallet create software p --store-seed-phrase=f", 46);
        assert_eq!(
            values(&suggestions),
            vec!["false"],
            "the inline =-form must complete flag values"
        );
    }

    #[test]
    fn flags_are_offered_and_taken_ones_skipped() {
        let mut completer = completer();
        let suggestions = completer.complete("broadcast --", 12);
        let all = values(&suggestions);
        assert_eq!(all, vec!["--broadcast", "--help"]);
        let suggestions = completer.complete("broadcast --broadcast yes --", 28);
        let remaining = values(&suggestions);
        assert!(!remaining.contains(&"--broadcast"));
    }

    #[test]
    fn enum_values_are_offered_for_flags_and_positionals() {
        let mut completer = completer();
        let suggestions = completer.complete("broadcast --broadcast ", 22);
        let after_flag = values(&suggestions);
        assert_eq!(after_flag, vec!["no", "yes"]);
        let suggestions = completer.complete("group status ", 13);
        let positional = values(&suggestions);
        assert_eq!(positional, vec!["full", "short"]);
    }

    #[test]
    fn short_flags_are_not_counted_as_positionals() {
        let mut completer = completer();
        let suggestions = completer.complete("group status -h ", 16);
        assert_eq!(values(&suggestions), vec!["full", "short"]);
    }

    #[test]
    fn inline_flag_values_satisfy_the_flag() {
        let mut completer = completer();
        let suggestions = completer.complete("broadcast --broadcast=yes --", 29);
        let offered = values(&suggestions);
        assert!(!offered.contains(&"--broadcast"));
        let suggestions = completer.complete("broadcast --broadcast=yes ", 26);
        assert!(values(&suggestions).is_empty());
    }

    #[test]
    fn partial_inline_values_complete_after_the_equals_sign() {
        let mut completer = completer();
        let suggestions = completer.complete("broadcast --broadcast=y", 23);
        assert_eq!(values(&suggestions), vec!["yes"]);
        assert_eq!(suggestions[0].span, Span::new(22, 23));
    }

    #[test]
    fn hidden_subcommands_resolve_when_typed() {
        let mut completer = completer();
        // Hidden commands are not offered in the menu...
        assert!(!values(&completer.complete("", 0)).contains(&"sweep"));
        // ...but resolve once typed.
        let suggestions = completer.complete("sweep ", 6);
        assert_eq!(values(&suggestions), vec!["no", "yes"]);
    }

    #[test]
    fn descriptions_carry_the_help_text() {
        let mut completer = completer();
        let suggestions = completer.complete("group status ", 13);
        assert_eq!(suggestions[0].description.as_deref(), Some("Everything"));
    }

    #[test]
    fn create_software_completes_the_storage_flag_and_its_values() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);

        // Double TAB after the command (and after the path) offers the flags:
        // the storage flag and the passphrase flag; the hidden legacy
        // positional and its values are not offered.
        let suggestions = completer.complete("wallet create software ", 23);
        let offered = values(&suggestions);
        assert!(
            offered.contains(&"--store-seed-phrase"),
            "the storage flag must be offered\n{offered:?}"
        );
        assert!(
            offered.contains(&"--passphrase"),
            "the passphrase flag must be offered\n{offered:?}"
        );
        assert!(
            !offered.contains(&"store-seed-phrase"),
            "the hidden positional's values must not be advertised\n{offered:?}"
        );
        assert!(
            !offered.contains(&"do-not-store-seed-phrase"),
            "the hidden positional's values must not be advertised\n{offered:?}"
        );
        // ...but input that already prefix-matches one of them is finished.
        // The hidden storage slot is the second positional: after the path is
        // typed, a prefix that matches a legacy value finishes it.
        // A single keystroke is not enough to surface the hidden values.
        let prefix_suggestions = completer.complete("wallet create software p d", 27);
        assert!(
            values(&prefix_suggestions).is_empty(),
            "a one-character prefix must not advertise hidden values"
        );
        let prefix_suggestions = completer.complete("wallet create software p do-", 28);
        assert_eq!(
            values(&prefix_suggestions),
            vec!["do-not-store-seed-phrase"],
            "the legacy value must be completable on prefix"
        );
        let prefix_suggestions = completer.complete("wallet create software p st", 27);
        assert_eq!(
            values(&prefix_suggestions),
            vec!["store-seed-phrase"],
            "the legacy value must be completable on prefix"
        );

        // After the path, the flags are still offered (including the
        // headline --mnemonic); the auto --help stays out of the fallback
        // menu, and the hidden legacy positional's values stay unadvertised.
        let suggestions = completer.complete("wallet create software p ", 25);
        let offered = values(&suggestions);
        assert!(
            offered.contains(&"--store-seed-phrase"),
            "the storage flag must be offered\n{offered:?}"
        );
        assert!(
            offered.contains(&"--mnemonic"),
            "the mnemonic flag must be offered\n{offered:?}"
        );
        assert!(
            !offered.contains(&"store-seed-phrase"),
            "the hidden positional's values must not be advertised\n{offered:?}"
        );
        assert!(
            !offered.contains(&"do-not-store-seed-phrase"),
            "the hidden positional's values must not be advertised\n{offered:?}"
        );
        assert!(
            !offered.contains(&"--help"),
            "the fallback menu must not offer --help\n{offered:?}"
        );

        // The flag's value completes to true/false.
        let flag_suggestions =
            completer.complete("wallet create software p --store-seed-phrase ", 45);
        let after_flag = values(&flag_suggestions);
        assert_eq!(after_flag, vec!["false", "true"]);

        // A given flag is taken: it stops being offered while its siblings
        // remain.
        let suggestions = completer.complete("wallet create software p --passphrase x ", 40);
        let offered = values(&suggestions);
        assert!(
            !offered.contains(&"--passphrase"),
            "the taken flag must not be offered\n{offered:?}"
        );
        assert!(
            offered.contains(&"--store-seed-phrase"),
            "the storage flag must still be offered\n{offered:?}"
        );

        // An exhausted enumerated slot previously offered nothing; the
        // fallback now offers the command's flags (minus --help).
        let small =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut small_completer = WalletCompletions::new(small);
        let suggestions = small_completer.complete("group status full ", 18);
        let offered = values(&suggestions);
        assert!(
            !offered.contains(&"full") && !offered.contains(&"short"),
            "the consumed slot's values must not be re-offered\n{offered:?}"
        );
        assert!(
            !offered.contains(&"--help"),
            "the fallback menu must not offer --help\n{offered:?}"
        );

        // A second, unrelated real-grammar leaf also gains the flag fallback
        // (guards against accidental menu drift on other commands).
        let suggestions = completer.complete("send ", 5);
        let offered = values(&suggestions);
        assert!(
            !offered.contains(&"--help"),
            "the fallback menu must not offer --help\n{offered:?}"
        );

        // ...and positions under the root help topics never get the flag
        // fallback: their leaves are help topics, not commands.
        let suggestions = completer.complete("help wallet create ", 19);
        assert!(
            values(&suggestions).contains(&"software"),
            "help topics stay completable\n{offered:?}"
        );
        let suggestions = completer.complete("help wallet create software ", 28);
        assert!(
            values(&suggestions).is_empty(),
            "help topic leaves must not receive the flag fallback\n{offered:?}"
        );

        // The recover variant's hidden slot also stays unadvertised, while the
        // --mnemonic flag (required there) stays offered.
        let suggestions = completer.complete("wallet recover software p ", 26);
        let offered = values(&suggestions);
        assert!(
            !offered.contains(&"store-seed-phrase"),
            "recover's hidden slot values must not be advertised\n{offered:?}"
        );
        assert!(
            !offered.contains(&"do-not-store-seed-phrase"),
            "recover's hidden slot values must not be advertised\n{offered:?}"
        );
        assert!(
            offered.contains(&"--mnemonic"),
            "recover's fallback menu must offer --mnemonic\n{offered:?}"
        );

        // The headline --mnemonic flag is offered on the create side too.
        let suggestions = completer.complete("wallet create software p ", 25);
        let offered = values(&suggestions);
        assert!(
            offered.contains(&"--mnemonic"),
            "the fallback menu must offer --mnemonic\n{offered:?}"
        );

        // The Append --store-seed-phrase flag remains offered after being
        // given once (agreeing repeats are accepted).
        let suggestions =
            completer.complete("wallet create software p --store-seed-phrase=true ", 42);
        let offered = values(&suggestions);
        assert!(
            offered.contains(&"--store-seed-phrase"),
            "the repeatable storage flag must stay offered\n{offered:?}"
        );
    }

    #[rstest]
    fn advertised_help_views_stay_completable(
        #[values((false, true), (true, false), (true, true))] (cold_wallet, mutable_wallet): (
            bool,
            bool,
        ),
    ) {
        let grammar = wallet_cli_commands::run_with_large_stack(move || {
            build_repl_command(cold_wallet, mutable_wallet)
        });
        let mut completer = WalletCompletions::new(grammar);

        // At the root, both advertised views are offered.
        let root_suggestions = completer.complete("", 0);
        let at_root = values(&root_suggestions);
        assert!(
            at_root.contains(&"help full"),
            "the root menu must offer `help full`"
        );
        assert!(
            at_root.contains(&"legacy"),
            "the root menu must offer `legacy`"
        );

        // `help f` completes the `full` view; `leg` completes `legacy`.
        assert_eq!(values(&completer.complete("help f", 6)), vec!["full"]);
        assert_eq!(values(&completer.complete("leg", 3)), vec!["legacy"]);

        // Every group carries its own auto `help`, where `help full` does not
        // parse; the `full` offer must stay scoped to the root's `help`. (The
        // cold grammars have no `group`, so this falls to the root menu where
        // nothing matches the full path either.)
        assert_eq!(
            values(&completer.complete("group help f", 13)),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn hints_stay_clean_on_flag_fallback_menus() {
        // The ghost-hint channel must not surface fallback flags: after a
        // path token, the fallback menu offers --mnemonic etc., but the dimmed
        // hint would trail the cursor and mid-token acceptance would corrupt
        // the user's own path token.
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);

        // After the path: the fallback offers flags, but the FIRST candidate
        // (which is what the hint shows) is a path-completable token, not a
        // flag; nothing flag-like is inserted by accepting the hint since the
        // hint is suppressed below.
        let suggestions = completer.complete("wallet create software p ", 25);
        assert!(
            suggestions.iter().any(|s| s.value == "--mnemonic"),
            "the fallback menu offers --mnemonic (menu-level contract)"
        );

        // Mid-token on a path: the fallback must not produce flag candidates
        // that would corrupt the user's own token.
        let suggestions = completer.complete("wallet create software m", 26);
        let mid_token = values(&suggestions);
        assert!(
            mid_token.iter().all(|value| !value.starts_with("--")),
            "mid-token fallback candidates corrupt the path token: {mid_token:?}"
        );
    }

    #[test]
    fn hint_mode_suppresses_the_leaf_flag_fallback() {
        let grammar =
            wallet_cli_commands::run_with_large_stack(move || build_repl_command(false, true));
        let mut completer = WalletCompletions::new(grammar);
        completer.set_hint_mode(true);

        // After a path token: the TAB menu offers the fallback flags; the
        // ghost-hint channel is kept clean by hint-mode suppression plus the
        // final prefix filter (not by candidate ordering).
        let suggestions = completer.complete("wallet create software p ", 25);
        assert!(
            values(&suggestions).is_empty(),
            "hint mode must suppress the leaf flag fallback\n{suggestions:?}"
        );

        // Mid-token on a free-form path: no flags may leak into the hint.
        let suggestions = completer.complete("wallet create software m", 26);
        assert!(
            values(&suggestions).is_empty(),
            "hint mode must not offer flags mid-token\n{suggestions:?}"
        );

        // Hint mode preserves enumerated-slot hints: the suppression is gated
        // on the slot being empty, not applied blanket (TestCommand grammar:
        // `group status` enumerates full | short).
        let mut small = WalletCompletions::new(TestCommand::command());
        small.set_hint_mode(true);
        let suggestions = small.complete("group status ", 13);
        assert_eq!(values(&suggestions), vec!["full", "short"]);
    }

    #[test]
    fn hinter_shows_the_untyped_remainder() {
        let mut hinter = WalletHinter::new(completer());
        // `with_file` opens (and therefore creates) the file eagerly; use a
        // process-unique path and remove it afterwards.
        let history_file = std::env::temp_dir().join(format!(
            "wallet-completions-test-history-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let history: Box<dyn History> =
            Box::new(reedline::FileBackedHistory::with_file(100, history_file.clone()).unwrap());
        let hint = hinter.handle("se", 2, history.as_ref(), false, "");
        drop(history);
        let _ = std::fs::remove_file(history_file);
        assert_eq!(hint, "nd");
        assert_eq!(hinter.complete_hint(), "nd");
        assert_eq!(hinter.next_hint_token(), "nd");
    }
}
