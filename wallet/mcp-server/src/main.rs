// Copyright (c) 2024 RBB S.r.l
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

use std::path::PathBuf;

use clap::Parser;
use crypto::key::hdkd::u31::U31;
use rpc::RpcAuthData;
use serde_json::Value;
use wallet_mcp_server::{
    JSONRPC_VERSION, ReadonlyWallet, UtxoStateSelector, WithLockedSelector, handle_message,
};
use wallet_rpc_client::rpc_client::ClientWalletRpc;
use wallet_rpc_client::wallet_rpc_traits::WalletInterface;
use wallet_types::utxo_types::UtxoState;
use wallet_types::with_locked::WithLocked;

#[derive(Debug, Parser)]
#[clap(
    name = "wallet-mcp-server",
    about = "Read-only MCP server for a Mintlayer wallet RPC daemon"
)]
#[clap(group(
    clap::ArgGroup::new("auth")
        .required(true)
        .args(["rpc_cookie_file", "rpc_username", "rpc_no_auth"]),
))]
struct CliArgs {
    /// Address of the wallet RPC daemon, e.g. 127.0.0.1:8332
    #[clap(long)]
    wallet_rpc_address: String,

    /// Cookie file used for authentication against the daemon
    #[clap(long, conflicts_with_all = &["rpc_username", "rpc_password", "rpc_no_auth"])]
    rpc_cookie_file: Option<PathBuf>,

    /// Username for basic authentication
    #[clap(long, requires = "rpc_password", conflicts_with_all = &["rpc_cookie_file", "rpc_no_auth"])]
    rpc_username: Option<String>,

    /// Password for basic authentication.
    ///
    /// Prefer `--rpc-cookie-file`; a password passed on the command line is
    /// visible to other local users via `ps` or `/proc/<pid>/cmdline`.
    #[clap(
        long,
        env = "WALLET_MCP_RPC_PASSWORD",
        hide_env_values = true,
        requires = "rpc_username",
        conflicts_with_all = &["rpc_cookie_file", "rpc_no_auth"]
    )]
    rpc_password: Option<String>,

    /// Connect without authentication
    #[clap(long, conflicts_with_all = &["rpc_cookie_file", "rpc_username", "rpc_password"])]
    rpc_no_auth: bool,
}

impl CliArgs {
    fn auth_data(&self) -> Result<RpcAuthData, String> {
        // The auth group is required, so exactly one branch applies; a new
        // group member missing here fails with a message instead of a panic.
        if let Some(cookie_file_path) = self.rpc_cookie_file.clone() {
            Ok(RpcAuthData::Cookie { cookie_file_path })
        } else if let (Some(username), Some(password)) =
            (self.rpc_username.clone(), self.rpc_password.clone())
        {
            Ok(RpcAuthData::Basic { username, password })
        } else if self.rpc_no_auth {
            Ok(RpcAuthData::None)
        } else {
            Err("exactly one of --rpc-cookie-file, --rpc-username with --rpc-password, or --rpc-no-auth must be provided"
                .to_owned())
        }
    }
}

/// Labels wallet RPC failures at the adapter boundary so tool results name
/// their provenance instead of surfacing a bare daemon message. The full
/// daemon error is echoed to standard error for server-side diagnostics;
/// the tool result carries the same text since the daemon and this server
/// share a trusted local operator.
// Diagnostics must not kill the protocol loop: a broken stderr (e.g. a
// client that closed its end of the pipe) is not a fatal server error.
fn log_rpc_error(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "[wallet-mcp] {message}");
}

fn rpc_error(err: impl std::fmt::Display) -> String {
    let message = format!("wallet RPC failed: {err}");
    log_rpc_error(&message);
    message
}

/// Adapter that exposes only the read-only operations of the daemon client.
struct RpcWallet(ClientWalletRpc);

impl ReadonlyWallet for RpcWallet {
    async fn version(&self) -> Result<String, String> {
        WalletInterface::version(&self.0).await.map_err(rpc_error)
    }

    async fn wallet_info(&self) -> Result<Value, String> {
        let info = WalletInterface::wallet_info(&self.0).await.map_err(rpc_error)?;
        serde_json::to_value(&info)
            .map_err(|err| format!("failed to serialize the wallet info: {err}"))
    }

    async fn best_block(&self) -> Result<Value, String> {
        let block = WalletInterface::best_block(&self.0).await.map_err(rpc_error)?;
        serde_json::to_value(&block)
            .map_err(|err| format!("failed to serialize the best block: {err}"))
    }

    async fn balance(
        &self,
        account_index: u32,
        utxo_states: Vec<UtxoStateSelector>,
        with_locked: WithLockedSelector,
    ) -> Result<Value, String> {
        let account_index = U31::from_u32(account_index)
            .ok_or_else(|| format!("Invalid account index: {account_index}"))?;
        let utxo_states = utxo_states.into_iter().map(utxo_state).collect();
        let balances = WalletInterface::get_balance(
            &self.0,
            account_index,
            utxo_states,
            with_locked_filter(with_locked),
        )
        .await
        .map_err(rpc_error)?;
        serde_json::to_value(&balances)
            .map_err(|err| format!("failed to serialize the balance: {err}"))
    }

    async fn standalone_addresses(&self, account_index: u32) -> Result<Value, String> {
        let account_index = U31::from_u32(account_index)
            .ok_or_else(|| format!("Invalid account index: {account_index}"))?;
        let addresses = WalletInterface::get_standalone_addresses(&self.0, account_index)
            .await
            .map_err(rpc_error)?;
        serde_json::to_value(&addresses)
            .map_err(|err| format!("failed to serialize the addresses: {err}"))
    }
}

fn utxo_state(selector: UtxoStateSelector) -> UtxoState {
    match selector {
        UtxoStateSelector::Confirmed => UtxoState::Confirmed,
        UtxoStateSelector::InMempool => UtxoState::InMempool,
        UtxoStateSelector::Conflicted => UtxoState::Conflicted,
        UtxoStateSelector::Inactive => UtxoState::Inactive,
        UtxoStateSelector::Abandoned => UtxoState::Abandoned,
    }
}

fn with_locked_filter(selector: WithLockedSelector) -> WithLocked {
    match selector {
        WithLockedSelector::Any => WithLocked::Any,
        WithLockedSelector::Unlocked => WithLocked::Unlocked,
        WithLockedSelector::Locked => WithLocked::Locked,
    }
}

/// Upper bound for a single protocol message, so a misbehaving peer cannot
/// make the server buffer unbounded input.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Upper bound on bytes discarded while resyncing after an oversized
/// message without a newline; past this the session is torn down.
const RESYNC_DRAIN_BUDGET: usize = MAX_MESSAGE_BYTES * 4;

/// Upper bound for one wallet RPC round trip; a daemon that hangs must not
/// stall the protocol loop past this.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Discards bytes up to and including the next newline. Gives up on the
/// stream if the line turns out to be endless.
async fn skip_rest_of_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let mut discarded: usize = 0;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(()); // EOF mid-line
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        discarded += available.len();
        if discarded > RESYNC_DRAIN_BUDGET {
            return Err(std::io::Error::other(
                "peer streamed an oversized message without a newline",
            ));
        }
        let len = available.len();
        reader.consume(len);
    }
}

async fn next_message<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Option<String>, std::io::Error> {
    use tokio::io::AsyncBufReadExt;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // End of stream: deliver a trailing message without a newline, if any.
            break;
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            if buffer.len() + pos > MAX_MESSAGE_BYTES {
                // Discard the rejected message so the stream stays usable;
                // leaving the bytes in place would trip this error forever.
                buffer.clear();
                reader.consume(pos + 1);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "message exceeds the maximum size",
                ));
            }
            buffer.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            let bytes: Vec<u8> = std::mem::take(buffer);
            // A protocol boundary must reject, not repair: lossy decoding could
            // silently turn a truncated request into a different valid one.
            let line = String::from_utf8(bytes)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            return Ok(Some(line));
        }
        if buffer.len() + available.len() > MAX_MESSAGE_BYTES {
            // The rejected line has no newline in this chunk; drain chunks
            // until its newline so exactly one error is reported per message.
            buffer.clear();
            skip_rest_of_line(reader).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message exceeds the maximum size",
            ));
        }
        buffer.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);
    }
    // The loop's `buffer.len() + available.len() > MAX_MESSAGE_BYTES` guard
    // runs before every extend, so a trailing message at EOF is already
    // bounded; no separate check is needed here.
    if buffer.is_empty() {
        return Ok(None);
    }
    let bytes = std::mem::take(buffer);
    let line = String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(Some(line))
}

async fn serve(wallet: RpcWallet) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut message_buffer = Vec::with_capacity(1024);
    let mut stdout = tokio::io::stdout();

    loop {
        // Malformed bytes and oversized messages are failures of the single
        // message, not of the stream: answer with a parse error and keep
        // serving instead of tearing the session down.
        // Recovery contract: every InvalidData from next_message has already
        // consumed or discarded the offending line (or hit EOF), so the next
        // iteration never re-reads the same bytes. The one error that must
        // NOT be recovered from — skip_rest_of_line's endless-line give-up —
        // uses io::Error::other on purpose; reclassifying it to InvalidData,
        // or adding an InvalidData path that does not resync, would spin
        // this loop forever.
        let line = match next_message(&mut reader, &mut message_buffer).await {
            Ok(line) => line,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                let encoded = serde_json::to_string(&serde_json::json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {err}")
                    }
                }))? + "\n";
                stdout.write_all(encoded.as_bytes()).await?;
                stdout.flush().await?;
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        let Some(line) = line else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(message) => {
                // Bound each request so a hung wallet daemon cannot stall the
                // protocol loop; the client gets a JSON-RPC error instead of
                // silence.
                match tokio::time::timeout(REQUEST_TIMEOUT, handle_message(&message, &wallet)).await
                {
                    Ok(response) => response,
                    Err(_elapsed) => {
                        log_rpc_error(&format!(
                            "wallet request timed out after {REQUEST_TIMEOUT:?}"
                        ));
                        message.get("id").cloned().map(|id| {
                            serde_json::json!({
                                "jsonrpc": JSONRPC_VERSION,
                                "id": id,
                                "error": { "code": -32000, "message": "wallet request timed out" }
                            })
                        })
                    }
                }
            }
            Err(err) => Some(serde_json::json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": null,
                "error": { "code": -32700, "message": format!("Parse error: {err}") }
            })),
        };
        if let Some(response) = response {
            let mut encoded = serde_json::to_string(&response)?;
            encoded.push('\n');
            stdout.write_all(encoded.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    let auth_data = match args.auth_data() {
        Ok(auth_data) => auth_data,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let wallet = match ClientWalletRpc::new(args.wallet_rpc_address.clone(), auth_data).await {
        Ok(client) => RpcWallet(client),
        Err(err) => {
            eprintln!("Failed to connect to the wallet RPC daemon: {err}");
            std::process::exit(1);
        }
    };
    // Standard output belongs to the protocol; diagnostics go to stderr.
    if let Err(err) = serve(wallet).await {
        eprintln!("MCP server stopped: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn next_n_messages(
        input: &str,
        count: usize,
        capacity: usize,
    ) -> Vec<Result<Option<String>, std::io::Error>> {
        let mut reader = tokio::io::BufReader::with_capacity(capacity, input.as_bytes());
        let mut buffer = Vec::new();
        let mut results = Vec::new();
        for _ in 0..count {
            results.push(next_message(&mut reader, &mut buffer).await);
        }
        results
    }

    #[tokio::test]
    async fn oversized_message_is_skipped_and_stream_stays_usable() {
        let input = format!(
            "{}\n{{\"method\":\"ping\"}}\n",
            "x".repeat(MAX_MESSAGE_BYTES + 1)
        );
        let results = next_n_messages(&input, 2, 8192).await;
        let err = results[0].as_ref().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            results[1].as_ref().unwrap().as_deref(),
            Some("{\"method\":\"ping\"}")
        );
    }

    #[tokio::test]
    async fn oversized_message_spanning_chunks_resyncs() {
        let input = format!(
            "{}\n{{\"method\":\"ping\"}}\n",
            "y".repeat(MAX_MESSAGE_BYTES + 1)
        );
        // A tiny read buffer forces the oversized line through many chunks.
        let results = next_n_messages(&input, 2, 64).await;
        assert_eq!(
            results[0].as_ref().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(results[1].as_ref().unwrap().is_some());
    }

    #[tokio::test]
    async fn oversized_message_without_newline_reports_once_at_eof() {
        let input = "z".repeat(MAX_MESSAGE_BYTES + 1);
        let results = next_n_messages(&input, 2, 8192).await;
        assert_eq!(
            results[0].as_ref().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(results[1].as_ref().unwrap(), &None);
    }
}
