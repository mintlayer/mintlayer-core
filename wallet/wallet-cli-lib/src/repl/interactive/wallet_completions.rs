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

use clap::{Arg, ArgAction, Command};
use reedline::{Completer, Hinter, Span, Suggestion};

/// A completer that walks the clap command tree, offering subcommand names,
/// long flags, and enumeration values for the token in front of the cursor.
#[derive(Clone)]
pub struct WalletCompletions {
    root: std::sync::Arc<Command>,
}

impl WalletCompletions {
    pub fn new(mut root: Command) -> Self {
        root.build();
        Self {
            root: std::sync::Arc::new(root),
        }
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
        let description = sub.get_about().map(|about| about.to_string());
        candidates.push(Candidate {
            value: sub.get_name().to_owned(),
            description: description.clone(),
        });
        for alias in sub.get_all_aliases() {
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
    arg.get_possible_values()
        .into_iter()
        .map(|value| Candidate {
            value: value.get_name().to_owned(),
            description: value.get_help().map(|help| help.to_string()),
        })
        .collect()
}

fn value_candidates(pending_value_flag: Option<&Arg>) -> Vec<Candidate> {
    let Some(arg) = pending_value_flag else {
        return Vec::new();
    };
    arg.get_possible_values()
        .into_iter()
        .map(|value| Candidate {
            value: value.get_name().to_owned(),
            description: value.get_help().map(|help| help.to_string()),
        })
        .collect()
}

/// Walk the tokenized prefix of the line and return the command level the
/// cursor sits at, the long flags already given at that level, the number of
/// positional values consumed, and a flag whose value is still missing.
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
        if let Some(sub) = cmd.find_subcommand(token).filter(|sub| !sub.is_hide_set()) {
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
        let prefix = line.get(..pos).unwrap_or(line);
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
        let candidates = if current.starts_with("--") {
            flag_candidates(level.cmd, &level.taken_flags)
        } else if level.pending_value_flag.is_some() {
            value_candidates(level.pending_value_flag)
        } else {
            let mut candidates = subcommand_candidates(level.cmd);
            candidates.extend(positional_candidates(level.cmd, level.positional_index));
            candidates
        };

        let start = pos.saturating_sub(current.len());
        candidates
            .into_iter()
            .filter(|candidate| candidate.value.starts_with(current))
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
}

impl WalletHinter {
    pub fn new(completer: WalletCompletions) -> Self {
        Self {
            completer,
            current_hint: String::new(),
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
        self.current_hint = self
            .completer
            .complete(line, pos)
            .first()
            .map(|suggestion| {
                let typed = pos.saturating_sub(suggestion.span.start);
                suggestion.value.get(typed..).unwrap_or_default().to_owned()
            })
            .unwrap_or_default();
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
        assert_eq!(values, vec!["send", "broadcast", "group", "help"]);
    }

    #[test]
    fn nested_subcommands_are_offered_after_the_group() {
        let mut completer = completer();
        let suggestions = completer.complete("group ", 6);
        assert_eq!(values(&suggestions), vec!["status", "help"]);
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
        assert_eq!(after_flag, vec!["yes", "no"]);
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
    fn descriptions_carry_the_help_text() {
        let mut completer = completer();
        let suggestions = completer.complete("group status ", 13);
        assert_eq!(suggestions[0].description.as_deref(), Some("Everything"));
    }

    #[test]
    fn hinter_shows_the_untyped_remainder() {
        let mut hinter = WalletHinter::new(completer());
        let history_file = std::env::temp_dir().join(format!(
            "wallet-completions-test-history-{}",
            std::process::id()
        ));
        let history: Box<dyn History> =
            Box::new(reedline::FileBackedHistory::with_file(100, history_file).unwrap());
        let hint = hinter.handle("se", 2, history.as_ref(), false, "");
        assert_eq!(hint, "nd");
        assert_eq!(hinter.complete_hint(), "nd");
        assert_eq!(hinter.next_hint_token(), "nd");
    }
}
