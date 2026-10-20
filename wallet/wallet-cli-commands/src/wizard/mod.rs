// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Interactive collection of command arguments ("wizards").
//!
//! A wizard asks the same questions the command line would, validates every
//! answer, shows a summary, and produces the equivalent one-liner command. The
//! one-liner is fed back through the regular command parser, so a wizard is
//! only a different way to type the same command, never a second execution
//! path.

use std::collections::VecDeque;

/// Where wizard answers come from. The production backend asks on the
/// terminal; tests feed canned answers.
pub trait PromptBackend {
    fn text(&mut self, prompt: &str, default: Option<&str>) -> Result<String, WizardError>;
    fn select(&mut self, prompt: &str, options: &[&str]) -> Result<usize, WizardError>;
    fn confirm(&mut self, prompt: &str) -> Result<bool, WizardError>;
}

#[derive(Debug)]
pub enum WizardError {
    /// The user declined (summary confirmation or an earlier prompt).
    Cancelled,
    /// The terminal conversation failed.
    Io(std::io::Error),
    /// An answer is unusable.
    InvalidInput(String),
}

impl std::fmt::Display for WizardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidInput(message) => write!(f, "{message}"),
        }
    }
}

impl From<std::io::Error> for WizardError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<dialoguer::Error> for WizardError {
    fn from(err: dialoguer::Error) -> Self {
        Self::Io(std::io::Error::other(err.to_string()))
    }
}

/// Asks on the terminal with the default `dialoguer` styling.
pub struct DialoguerBackend;

impl PromptBackend for DialoguerBackend {
    fn text(&mut self, prompt: &str, default: Option<&str>) -> Result<String, WizardError> {
        let input = dialoguer::Input::<String>::new()
            .with_prompt(prompt.to_owned())
            .with_post_completion_text("");
        let input = if let Some(default) = default {
            input.default(default.to_owned())
        } else {
            input
        };
        Ok(input.interact_text()?)
    }

    fn select(&mut self, prompt: &str, options: &[&str]) -> Result<usize, WizardError> {
        Ok(
            dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(prompt.to_owned())
                .items(options)
                .default(0)
                .interact()?,
        )
    }

    fn confirm(&mut self, prompt: &str) -> Result<bool, WizardError> {
        Ok(dialoguer::Confirm::new().with_prompt(prompt).default(true).interact()?)
    }
}

/// Test backend: replays scripted answers in order.
#[derive(Default)]
pub struct CannedBackend {
    answers: VecDeque<CannedAnswer>,
}

pub enum CannedAnswer {
    Text(String),
    Select(usize),
    Confirm(bool),
}

impl CannedBackend {
    pub fn new(answers: impl IntoIterator<Item = CannedAnswer>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
        }
    }

    fn next(&mut self) -> Result<CannedAnswer, WizardError> {
        self.answers.pop_front().ok_or_else(|| {
            WizardError::InvalidInput("the wizard ran out of scripted answers".to_owned())
        })
    }
}

impl PromptBackend for CannedBackend {
    fn text(&mut self, _prompt: &str, _default: Option<&str>) -> Result<String, WizardError> {
        match self.next()? {
            CannedAnswer::Text(answer) => Ok(answer),
            _ => Err(WizardError::InvalidInput(
                "expected a text answer".to_owned(),
            )),
        }
    }

    fn select(&mut self, _prompt: &str, _options: &[&str]) -> Result<usize, WizardError> {
        match self.next()? {
            CannedAnswer::Select(index) => Ok(index),
            _ => Err(WizardError::InvalidInput(
                "expected a selection answer".to_owned(),
            )),
        }
    }

    fn confirm(&mut self, _prompt: &str) -> Result<bool, WizardError> {
        match self.next()? {
            CannedAnswer::Confirm(answer) => Ok(answer),
            _ => Err(WizardError::InvalidInput(
                "expected a confirmation answer".to_owned(),
            )),
        }
    }
}

fn require_non_empty(field: &str, answer: &str) -> Result<String, WizardError> {
    if answer.trim().is_empty() {
        Err(WizardError::InvalidInput(format!("{field} is required")))
    } else {
        Ok(answer.trim().to_owned())
    }
}

/// Shell-quotes a value so the produced one-liner round-trips through the
/// same word splitting the REPL uses.
fn quote(value: &str) -> String {
    shlex::try_quote(value).map_or_else(|_| value.to_owned(), std::borrow::Cow::into_owned)
}

fn optional_field(answer: &str) -> Option<String> {
    let trimmed = answer.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Summarizes the collected answers and asks for confirmation. Returns an
/// error when the user declines.
fn confirm_summary(backend: &mut impl PromptBackend, lines: &[String]) -> Result<(), WizardError> {
    let mut summary = String::from("Summary:\n");
    for line in lines {
        summary.push_str("  ");
        summary.push_str(line);
        summary.push('\n');
    }
    println!("{summary}");
    if backend.confirm("Create the command from these values?")? {
        Ok(())
    } else {
        Err(WizardError::Cancelled)
    }
}

/// `token issue <ticker> <decimals> <metadata-uri> <authority> <supply> <freezable>`
pub fn token_issue(backend: &mut impl PromptBackend) -> Result<String, WizardError> {
    let ticker = require_non_empty("ticker", &backend.text("Token ticker:", None)?)?;
    let decimals: u8 =
        backend.text("Number of decimals:", Some("8"))?.trim().parse().map_err(|_| {
            WizardError::InvalidInput("the number of decimals must be 0-255".to_owned())
        })?;
    let metadata_uri = require_non_empty("metadata URI", &backend.text("Metadata URI:", None)?)?;
    let authority = require_non_empty(
        "authority address",
        &backend.text("Authority address:", None)?,
    )?;
    let supply = match backend.select("Token supply:", &["unlimited", "lockable", "fixed"])? {
        0 => "unlimited".to_owned(),
        1 => "lockable".to_owned(),
        _ => {
            let amount = require_non_empty("amount", &backend.text("Fixed supply amount:", None)?)?;
            format!("fixed({amount})")
        }
    };
    let freezable = match backend.select(
        "Can the token authority freeze accounts?",
        &["not-freezable", "freezable"],
    )? {
        0 => "not-freezable",
        _ => "freezable",
    };
    confirm_summary(
        backend,
        &[
            format!("Ticker: {ticker}"),
            format!("Decimals: {decimals}"),
            format!("Metadata URI: {metadata_uri}"),
            format!("Authority: {authority}"),
            format!("Supply: {supply}"),
            format!("Freezable: {freezable}"),
        ],
    )?;
    Ok(format!(
        "token issue {} {decimals} {} {} {supply} {freezable}",
        quote(&ticker),
        quote(&metadata_uri),
        quote(&authority)
    ))
}

/// `token nft issue <destination> <media-hash> <name> <description> <ticker> [creator] [icon-uri] [media-uri] [additional-metadata-uri]`
///
/// Optional answers must be filled in order: clap positionals cannot skip a
/// middle value, so once one is left empty the remaining ones are ignored.
pub fn token_nft_issue(backend: &mut impl PromptBackend) -> Result<String, WizardError> {
    let destination = require_non_empty(
        "destination address",
        &backend.text("Destination address:", None)?,
    )?;
    let media_hash = require_non_empty("media hash", &backend.text("Media hash (hex):", None)?)?;
    let name = require_non_empty("name", &backend.text("NFT name:", None)?)?;
    let description = backend.text("Description:", None)?;
    let ticker = require_non_empty("ticker", &backend.text("Ticker:", None)?)?;
    let creator = backend.text("Creator public key (hex, empty to omit):", None)?;
    let icon_uri = backend.text("Icon URI (empty to omit):", None)?;
    let media_uri = backend.text("Media URI (empty to omit):", None)?;
    let additional_metadata_uri = backend.text("Additional metadata URI (empty to omit):", None)?;

    let optionals = [creator, icon_uri, media_uri, additional_metadata_uri]
        .into_iter()
        .map(|answer| optional_field(&answer));
    let mut rendered_optionals = Vec::new();
    let mut saw_empty = false;
    for optional in optionals {
        match (optional, saw_empty) {
            (Some(value), false) => rendered_optionals.push(value),
            (Some(_), true) => {
                return Err(WizardError::InvalidInput(
                    "optional NFT fields must be filled in order; an empty answer ends the \
                     optional fields"
                        .to_owned(),
                ));
            }
            (None, _) => saw_empty = true,
        }
    }

    confirm_summary(
        backend,
        &[
            format!("Destination: {destination}"),
            format!("Media hash: {media_hash}"),
            format!("Name: {name}"),
            format!("Description: {}", description.trim()),
            format!("Ticker: {ticker}"),
        ],
    )?;
    let mut line = format!(
        "token nft issue {} {} {} {} {}",
        quote(&destination),
        quote(&media_hash),
        quote(&name),
        quote(description.trim()),
        quote(&ticker)
    );
    for optional in rendered_optionals {
        line.push(' ');
        line.push_str(&quote(&optional));
    }
    Ok(line)
}

/// `staking create-pool <amount> <cost-per-block> <margin-ratio-per-mille> <decommission-address> [staker] [vrf-public-key]`
pub fn staking_pool_create(backend: &mut impl PromptBackend) -> Result<String, WizardError> {
    let amount = require_non_empty(
        "pledge amount",
        &backend.text("Pledge amount (locked until decommission):", None)?,
    )?;
    let cost_per_block = {
        let answer = backend.text("Cost per block:", Some("0"))?;
        if answer.trim().is_empty() {
            "0".to_owned()
        } else {
            answer
        }
    };
    let margin_ratio = require_non_empty(
        "margin ratio",
        &backend.text("Margin ratio in per-mille (e.g. 100 = 10%):", None)?,
    )?;
    let decommission = require_non_empty(
        "decommission address",
        &backend.text("Decommission address (cold storage recommended):", None)?,
    )?;
    let staker = backend.text("Staker address (empty for this wallet):", None)?;
    let vrf = backend.text("VRF public key (empty for this wallet):", None)?;

    confirm_summary(
        backend,
        &[
            format!("Pledge amount: {amount} (locked until the pool is decommissioned)"),
            format!("Cost per block: {}", cost_per_block.trim()),
            format!("Margin ratio (per mille): {margin_ratio}"),
            format!("Decommission address: {decommission}"),
        ],
    )?;
    let mut line = format!(
        "staking create-pool {} {} {} {}",
        quote(&amount),
        quote(&cost_per_block),
        quote(&margin_ratio),
        quote(&decommission)
    );
    if let Some(staker) = optional_field(&staker) {
        line.push(' ');
        line.push_str(&staker);
        if let Some(vrf) = optional_field(&vrf) {
            line.push(' ');
            line.push_str(&vrf);
        }
    } else if optional_field(&vrf).is_some() {
        return Err(WizardError::InvalidInput(
            "the VRF public key requires a staker address to be set".to_owned(),
        ));
    }
    Ok(line)
}

/// `order create <ask-currency> <ask-amount> <give-currency> <give-amount> <conclude-address>`
pub fn order_create(backend: &mut impl PromptBackend) -> Result<String, WizardError> {
    fn currency(backend: &mut impl PromptBackend, side: &str) -> Result<String, WizardError> {
        match backend.select(&format!("{side} currency:"), &["coin", "token id"])? {
            0 => Ok("coin".to_owned()),
            _ => require_non_empty("token id", &backend.text("Token id:", None)?),
        }
    }
    let ask_currency = currency(backend, "Asked")?;
    let ask_amount = require_non_empty("ask amount", &backend.text("Asked amount:", None)?)?;
    let give_currency = currency(backend, "Given")?;
    let give_amount = require_non_empty("give amount", &backend.text("Given amount:", None)?)?;
    let conclude = require_non_empty(
        "conclude address",
        &backend.text("Conclude address:", None)?,
    )?;

    let implied_price = match (ask_amount.parse::<f64>(), give_amount.parse::<f64>()) {
        (Ok(ask), Ok(give)) if give != 0.0 => (ask / give).to_string(),
        _ => "?".to_owned(),
    };
    confirm_summary(
        backend,
        &[
            format!("Ask: {ask_amount} {ask_currency}"),
            format!("Give: {give_amount} {give_currency}"),
            format!("Conclude address: {conclude}"),
            format!("Implied price: 1 {give_currency} = {implied_price} {ask_currency}"),
        ],
    )?;
    Ok(format!(
        "order create {ask_currency} {} {give_currency} {} {}",
        quote(&ask_amount),
        quote(&give_amount),
        quote(&conclude)
    ))
}

/// `htlc create <currency> <amount> <secret-hash> <spend-address> <refund-timelock> <refund-address>`
///
/// The resulting transaction is built and shown, but never broadcast.
pub fn htlc_create(backend: &mut impl PromptBackend) -> Result<String, WizardError> {
    let currency_kind = backend.select("Currency to lock:", &["coin", "token id"])?;
    let currency = match currency_kind {
        0 => "coin".to_owned(),
        _ => require_non_empty("token id", &backend.text("Token id:", None)?)?,
    };
    let amount = require_non_empty("amount", &backend.text("Amount to lock:", None)?)?;
    let secret_hash = require_non_empty("secret hash", &backend.text("Secret hash (hex):", None)?)?;
    let spend = require_non_empty("spend address", &backend.text("Spend address:", None)?)?;
    let refund = require_non_empty("refund address", &backend.text("Refund address:", None)?)?;
    let timelock_kind = backend.select(
        "Refund timelock type:",
        &[
            "for a number of blocks",
            "for a number of seconds",
            "until a height",
            "until a time",
        ],
    )?;
    let timelock_name = ["block_count", "seconds", "until_height", "until_time"][timelock_kind];
    let timelock_value = require_non_empty(
        "timelock value",
        &backend.text(
            match timelock_kind {
                3 => "Refund time (RFC 3339):",
                _ => "Timelock value:",
            },
            None,
        )?,
    )?;

    confirm_summary(
        backend,
        &[
            format!("Locks: {amount} {currency}"),
            format!("Spend address (with the secret): {spend}"),
            format!("Refund address (after the timelock): {refund}"),
            format!("Refund timelock: {timelock_name}({timelock_value})"),
            "The transaction is NOT broadcast; the output is the raw transaction.".to_owned(),
        ],
    )?;
    Ok(format!(
        "htlc create {currency} {} {} {} {timelock_name}({}) {}",
        quote(&amount),
        quote(&secret_hash),
        quote(&spend),
        quote(&timelock_value),
        quote(&refund)
    ))
}

/// The commands that have an interactive argument collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardKind {
    TokenIssue,
    NftIssue,
    PoolCreate,
    OrderCreate,
    HtlcCreate,
}

impl WizardKind {
    /// Recognizes a wizard invocation in a line: either the explicit
    /// `wizard <sub-command>` spelling or one of the eligible command prefixes
    /// (`token issue`, `token nft issue`, `staking create-pool`,
    /// `order create`, `htlc create`).
    pub fn parse_from_tokens(tokens: &[&str]) -> Option<WizardKind> {
        match tokens {
            ["wizard", "token-issue"] => Some(WizardKind::TokenIssue),
            ["wizard", "nft-issue"] => Some(WizardKind::NftIssue),
            ["wizard", "pool-create"] => Some(WizardKind::PoolCreate),
            ["wizard", "order-create"] => Some(WizardKind::OrderCreate),
            ["wizard", "htlc-create"] => Some(WizardKind::HtlcCreate),
            ["token", "issue"] => Some(WizardKind::TokenIssue),
            ["token", "nft", "issue"] => Some(WizardKind::NftIssue),
            ["staking", "create-pool"] => Some(WizardKind::PoolCreate),
            ["order", "create"] => Some(WizardKind::OrderCreate),
            ["htlc", "create"] => Some(WizardKind::HtlcCreate),
            _ => None,
        }
    }

    /// Produces the command line this wizard generates.
    pub fn run(self, backend: &mut impl PromptBackend) -> Result<String, WizardError> {
        match self {
            WizardKind::TokenIssue => token_issue(backend),
            WizardKind::NftIssue => token_nft_issue(backend),
            WizardKind::PoolCreate => staking_pool_create(backend),
            WizardKind::OrderCreate => order_create(backend),
            WizardKind::HtlcCreate => htlc_create(backend),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(answers: impl IntoIterator<Item = CannedAnswer>) -> CannedBackend {
        CannedBackend::new(answers)
    }

    fn text<'a>(values: &'a [&'a str]) -> impl Iterator<Item = CannedAnswer> + 'a {
        values.iter().map(|value| CannedAnswer::Text((*value).to_owned()))
    }

    #[test]
    fn token_issue_one_liner_round_trips_through_the_parser() {
        let mut backend = backend(
            text(&["GOLD", "8", "https://example.com", "7Utx1"])
                .chain([CannedAnswer::Select(2)])
                .chain(text(&["100"]))
                .chain([CannedAnswer::Select(1), CannedAnswer::Confirm(true)]),
        );
        let line = token_issue(&mut backend).unwrap();
        assert_eq!(
            line,
            "token issue GOLD 8 https://example.com 7Utx1 fixed(100) freezable"
        );
    }

    #[test]
    fn declining_the_summary_is_reported_as_cancelled() {
        let mut backend = backend(
            text(&["GOLD", "8", "https://example.com", "addr"])
                .chain([CannedAnswer::Select(0), CannedAnswer::Select(0)])
                .chain([CannedAnswer::Confirm(false)]),
        );
        assert!(matches!(
            token_issue(&mut backend),
            Err(WizardError::Cancelled)
        ));
    }

    #[test]
    fn nft_optionals_stop_at_the_first_empty_answer() {
        let mut backend = backend(
            text(&["dest", "abcd", "Name", "Desc", "NFT", "cc", "https://icon", "", ""])
                .chain([CannedAnswer::Confirm(true)]),
        );
        let line = token_nft_issue(&mut backend).unwrap();
        assert_eq!(
            line,
            "token nft issue dest abcd Name Desc NFT cc https://icon"
        );
    }

    #[test]
    fn nft_optionals_must_be_filled_in_order() {
        let mut backend = backend(text(&[
            "dest",
            "abcd",
            "Name",
            "Desc",
            "NFT",
            "",
            "https://icon",
        ]));
        assert!(token_nft_issue(&mut backend).is_err());
    }

    #[test]
    fn pool_create_defaults_the_cost_and_requires_ordered_optionals() {
        let mut backend = backend(
            text(&["40000", "", "100", "cold", "", ""]).chain([CannedAnswer::Confirm(true)]),
        );
        let line = staking_pool_create(&mut backend).unwrap();
        assert_eq!(line, "staking create-pool 40000 0 100 cold");

        let mut with_optional_keys = CannedBackend::new(
            text(&["40000", "5", "100", "cold", "staker", "aabb"])
                .chain([CannedAnswer::Confirm(true)]),
        );
        let line = staking_pool_create(&mut with_optional_keys).unwrap();
        assert_eq!(line, "staking create-pool 40000 5 100 cold staker aabb");
    }

    #[test]
    fn order_create_renders_the_implied_rate() {
        let mut backend = backend(
            [CannedAnswer::Select(1)]
                .into_iter()
                .chain(text(&["tok1", "100"]))
                .chain([CannedAnswer::Select(0)])
                .chain(text(&["50", "addr"]))
                .chain([CannedAnswer::Confirm(true)]),
        );
        let line = order_create(&mut backend).unwrap();
        assert_eq!(line, "order create tok1 100 coin 50 addr");
    }

    #[test]
    fn htlc_create_pins_the_funclike_timelock() {
        let mut backend = backend(
            [CannedAnswer::Select(0)]
                .into_iter()
                .chain(text(&["50", "abcd", "spend", "refund"]))
                .chain([CannedAnswer::Select(0)])
                .chain(text(&["720"]))
                .chain([CannedAnswer::Confirm(true)]),
        );
        let line = htlc_create(&mut backend).unwrap();
        assert_eq!(
            line,
            "htlc create coin 50 abcd spend block_count(720) refund"
        );
    }
}
