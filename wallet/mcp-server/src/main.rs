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
use wallet_mcp_server::{ReadonlyWallet, UtxoStateSelector, WithLockedSelector, handle_message};
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
    fn auth_data(&self) -> RpcAuthData {
        // The auth group is required, so exactly one branch applies.
        if let Some(cookie_file_path) = self.rpc_cookie_file.clone() {
            RpcAuthData::Cookie { cookie_file_path }
        } else if let (Some(username), Some(password)) =
            (self.rpc_username.clone(), self.rpc_password.clone())
        {
            RpcAuthData::Basic { username, password }
        } else if self.rpc_no_auth {
            RpcAuthData::None
        } else {
            unreachable!("clap's `auth` arg group guarantees exactly one auth source")
        }
    }
}

/// Adapter that exposes only the read-only operations of the daemon client.
struct RpcWallet(ClientWalletRpc);

impl ReadonlyWallet for RpcWallet {
    async fn version(&self) -> Result<String, String> {
        WalletInterface::version(&self.0).await.map_err(|err| err.to_string())
    }

    async fn wallet_info(&self) -> Result<Value, String> {
        let info = WalletInterface::wallet_info(&self.0).await.map_err(|err| err.to_string())?;
        serde_json::to_value(&info).map_err(|err| err.to_string())
    }

    async fn best_block(&self) -> Result<Value, String> {
        let block = WalletInterface::best_block(&self.0).await.map_err(|err| err.to_string())?;
        serde_json::to_value(&block).map_err(|err| err.to_string())
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
        .map_err(|err| err.to_string())?;
        serde_json::to_value(&balances).map_err(|err| err.to_string())
    }

    async fn standalone_addresses(&self, account_index: u32) -> Result<Value, String> {
        let account_index = U31::from_u32(account_index)
            .ok_or_else(|| format!("Invalid account index: {account_index}"))?;
        let addresses = WalletInterface::get_standalone_addresses(&self.0, account_index)
            .await
            .map_err(|err| err.to_string())?;
        serde_json::to_value(&addresses).map_err(|err| err.to_string())
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "message exceeds the maximum size",
                ));
            }
            buffer.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            let line = String::from_utf8_lossy(buffer).into_owned();
            buffer.clear();
            return Ok(Some(line));
        }
        if buffer.len() + available.len() > MAX_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "protocol message exceeds the size limit",
            ));
        }
        buffer.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);
    }
    if buffer.is_empty() {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(buffer).into_owned();
    buffer.clear();
    Ok(Some(line))
}

async fn serve(wallet: RpcWallet) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut message_buffer = Vec::with_capacity(1024);
    let mut stdout = tokio::io::stdout();

    while let Some(line) = next_message(&mut reader, &mut message_buffer).await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(message) => handle_message(&message, &wallet).await,
            Err(err) => Some(serde_json::json!({
                "jsonrpc": "2.0",
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
    let wallet = match ClientWalletRpc::new(args.wallet_rpc_address.clone(), args.auth_data()).await
    {
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
