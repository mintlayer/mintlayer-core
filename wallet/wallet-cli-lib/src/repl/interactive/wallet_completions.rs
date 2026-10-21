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

/// A completer that walks the clap command tree, offering subcommand names,
/// long flags, and enumeration values for the token in front of the cursor.
#[derive(Clone)]
pub struct WalletCompletions {
    root: Arc<Command>,
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
        Self { root }
    }

    /// Takes an already-built grammar and trusts the caller: use this where
    /// the [`Command`] is shared behind an [`std::sync::Arc`] and the builder
    /// contract is known to hold (as with `build_repl_command` output).
    pub fn from_built(root: Arc<Command>) -> Self {
        Self { root }
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

/// Candidates for the positional argument at `index` (zero based) of `cmd`.
fn positional_candidates(cmd: &Command, index: usize) -> Vec<Candidate> {
    let positionals: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
        .collect();
    let arg = positionals.get(index).copied().or_else(|| {
        positionals
            .last()
            .copied()
            .filter(|last| matches!(last.get_action(), ArgAction::Append))
    });
    let Some(arg) = arg else {
        return Vec::new();
    };
    possible_value_candidates(arg.get_possible_values())
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
}

fn resolve_level<'a>(root: &'a Command, tokens: &[&str]) -> Level<'a> {
    let mut cmd = root;
    let mut taken_flags = BTreeSet::new();
    let mut positional_index = 0usize;
    let mut pending_value_flag: Option<&'a Arg> = None;
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
            candidates.extend(positional_candidates(level.cmd, level.positional_index));
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
        assert_eq!(values, vec!["broadcast", "group", "help", "send"]);
    }

    #[test]
    fn nested_subcommands_are_offered_after_the_group() {
        let mut completer = completer();
        let suggestions = completer.complete("group ", 6);
        assert_eq!(values(&suggestions), vec!["help", "status"]);
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
