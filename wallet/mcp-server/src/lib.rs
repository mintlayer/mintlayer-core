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

use serde_json::{Value, json};

/// The subset of wallet queries the server exposes.
// Only used through static dispatch; the auto-trait bound restriction of
// native async functions does not matter here.
#[allow(async_fn_in_trait)]
pub trait ReadonlyWallet {
    /// The current daemon version string.
    async fn version(&self) -> Result<String, String>;

    /// General wallet state (chains, accounts, sync status).
    async fn wallet_info(&self) -> Result<Value, String>;

    /// The best block the wallet has seen.
    async fn best_block(&self) -> Result<Value, String>;

    /// Balances for one account.
    async fn balance(
        &self,
        account_index: u32,
        utxo_states: Vec<UtxoStateSelector>,
        with_locked: WithLockedSelector,
    ) -> Result<Value, String>;

    /// Standalone addresses of one account.
    async fn standalone_addresses(&self, account_index: u32) -> Result<Value, String>;
}

/// UTXO states accepted by the balance tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtxoStateSelector {
    Confirmed,
    InMempool,
    Conflicted,
    Inactive,
    Abandoned,
}

impl UtxoStateSelector {
    /// Parses a state name; accepts the lowercase tool spelling.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "confirmed" => Some(Self::Confirmed),
            "in-mempool" => Some(Self::InMempool),
            "conflicted" => Some(Self::Conflicted),
            "inactive" => Some(Self::Inactive),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// Locked-UTXO filter accepted by the balance tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithLockedSelector {
    Any,
    Unlocked,
    Locked,
}

impl WithLockedSelector {
    /// Parses a filter name; defaults to unlocked UTXOs only.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "any" => Some(Self::Any),
            "unlocked" => Some(Self::Unlocked),
            "locked" => Some(Self::Locked),
            _ => None,
        }
    }
}

/// Descriptors of every tool the server offers. Read-only by design.
pub fn tool_definitions() -> Value {
    json!({
        "tools": [
            {
                "name": "version",
                "description": "Return the version of the connected wallet RPC daemon.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "wallet_info",
                "description": "Return general wallet state: chain, accounts and synchronization status.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "best_block",
                "description": "Return the best block known to the wallet.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "balance",
                "description": "Return the balances of one account.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account_index": { "type": "integer", "minimum": 0, "default": 0 },
                        "utxo_states": {
                            "type": "array",
                            "items": { "enum": ["confirmed", "in-mempool", "conflicted", "inactive", "abandoned"] },
                            "default": ["confirmed"]
                        },
                        "with_locked": { "enum": ["unlocked", "locked", "any"], "default": "unlocked" }
                    }
                }
            },
            {
                "name": "standalone_addresses",
                "description": "Return the standalone addresses of one account.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account_index": { "type": "integer", "minimum": 0, "default": 0 }
                    }
                }
            }
        ]
    })
}

/// Handles one decoded JSON-RPC message. Returns the response value for
/// requests and `None` for notifications.
/// The MCP protocol revisions this server implements, newest last; the
/// initialize handshake echoes a requested version only when it is listed here
/// and otherwise falls back to the newest one.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05"];

/// The JSON-RPC envelope version this server speaks (MCP transport).
pub const JSONRPC_VERSION: &str = "2.0";

pub async fn handle_message<W: ReadonlyWallet>(message: &Value, wallet: &W) -> Option<Value> {
    // Anything that is not a single request/notification object (a batched
    // array, a bare value) is not supported by this server; the advertised MCP
    // protocol version still permits batching, so answer with a single error
    // instead of leaving a conforming client waiting forever.
    if !message.is_object() {
        return Some(error_response(
            None,
            -32600,
            "Invalid Request: only single request objects are supported".to_owned(),
        ));
    }
    let id = message.get("id").cloned();
    // Notifications carry no id member and never get a response. A request
    // with an explicit null id still gets an answer, echoing the null back.
    message.get("id")?;
    if message.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        // JSON-RPC 2.0 requires the version member on every request.
        return Some(error_response(
            id,
            -32600,
            "Invalid Request: jsonrpc must be \"2.0\"".to_owned(),
        ));
    }
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // Requests must always be answered, even when malformed (JSON-RPC 2.0: -32600).
        return Some(error_response(
            id,
            -32600,
            "Invalid Request: missing or invalid method".to_owned(),
        ));
    };
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let response = match method {
        "initialize" => {
            // Echo the client's requested protocol version only when this
            // server actually supports it; unknown or missing versions fall
            // back to the newest supported entry, per the MCP initialize
            // handshake.
            let protocol_version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS.contains(requested))
                // The list is a non-empty const slice ordered newest last, so
                // the newest entry is always present and no literal is
                // duplicated here.
                .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS.last().expect("non-empty const"));
            result_response(
                id,
                json!({
                    "protocolVersion": protocol_version,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "mintlayer-wallet-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )
        }
        "ping" => result_response(id, json!({})),
        "tools/list" => result_response(id, tool_definitions()),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(error_response(
                    id,
                    -32602,
                    "Invalid params: `name` must be a string naming a tool".to_owned(),
                ));
            };
            let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            if !arguments.is_object() {
                return Some(error_response(
                    id,
                    -32602,
                    "Invalid params: `arguments` must be an object".to_owned(),
                ));
            }
            match call_tool(name, arguments, wallet).await {
                Ok(value) => match serde_json::to_string_pretty(&value) {
                    Ok(text) => result_response(id, tool_result(text, false)),
                    Err(err) => result_response(
                        id,
                        tool_result(format!("Failed to render the result: {err}"), true),
                    ),
                },
                // Argument and naming problems are protocol errors; only
                // failures of the wallet RPC itself are `isError` results.
                Err(ToolCallError::Protocol { code, message }) => error_response(id, code, message),
                Err(ToolCallError::Execution(message)) => {
                    result_response(id, tool_result(message, true))
                }
            }
        }
        other => error_response(id, -32601, format!("Method not found: {other}")),
    };
    Some(response)
}

/// A failed tool call: either a protocol-level problem (unknown tool,
/// malformed arguments) that must surface as a JSON-RPC error, or a failure of
/// the wallet RPC itself, which the MCP spec reports as an `isError` result.
enum ToolCallError {
    Protocol { code: i64, message: String },
    Execution(String),
}

impl ToolCallError {
    fn protocol(message: String) -> Self {
        Self::Protocol {
            code: -32602,
            message,
        }
    }
}

async fn call_tool<W: ReadonlyWallet>(
    name: &str,
    arguments: Value,
    wallet: &W,
) -> Result<Value, ToolCallError> {
    match name {
        "version" => wallet.version().await.map(Value::String).map_err(ToolCallError::Execution),
        "wallet_info" => wallet.wallet_info().await.map_err(ToolCallError::Execution),
        "best_block" => wallet.best_block().await.map_err(ToolCallError::Execution),
        "balance" => {
            let account_index = parse_account_index(&arguments).map_err(ToolCallError::protocol)?;
            let states = parse_utxo_states(&arguments).map_err(ToolCallError::protocol)?;
            let with_locked = match arguments.get("with_locked") {
                None | Some(Value::Null) => WithLockedSelector::Unlocked,
                Some(value) => {
                    value.as_str().and_then(WithLockedSelector::parse).ok_or_else(|| {
                        ToolCallError::protocol(format!("Invalid locked filter: {value}"))
                    })?
                }
            };
            wallet
                .balance(account_index, states, with_locked)
                .await
                .map_err(ToolCallError::Execution)
        }
        "standalone_addresses" => {
            let account_index = parse_account_index(&arguments).map_err(ToolCallError::protocol)?;
            wallet
                .standalone_addresses(account_index)
                .await
                .map_err(ToolCallError::Execution)
        }
        other => Err(ToolCallError::protocol(format!("Unknown tool: {other}"))),
    }
}

/// Parses the optional `account_index` argument, rejecting invalid values
/// instead of silently falling back to account 0.
fn parse_account_index(arguments: &Value) -> Result<u32, String> {
    match arguments.get("account_index") {
        None | Some(Value::Null) => Ok(0),
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                format!("account_index must be a non-negative integer, got: {value}")
            })?;
            u32::try_from(raw).map_err(|_| format!("account_index out of range: {raw}"))
        }
    }
}

fn parse_utxo_states(arguments: &Value) -> Result<Vec<UtxoStateSelector>, String> {
    let raw = arguments.get("utxo_states").cloned().unwrap_or(json!(["confirmed"]));
    let names = raw
        .as_array()
        .ok_or_else(|| "utxo_states must be an array of state names".to_owned())?;
    if names.is_empty() {
        return Err("utxo_states must not be empty".to_owned());
    }
    names
        .iter()
        .map(|name| {
            let name = name
                .as_str()
                .ok_or_else(|| "utxo_states must be an array of state names".to_owned())?;
            UtxoStateSelector::parse(name).ok_or_else(|| format!("Unknown UTXO state: {name}"))
        })
        .collect()
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": is_error
    })
}

fn result_response(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Option<Value>, code: i64, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubWallet;

    impl ReadonlyWallet for StubWallet {
        async fn version(&self) -> Result<String, String> {
            Ok("1.0.0+test".to_owned())
        }

        async fn wallet_info(&self) -> Result<Value, String> {
            Ok(json!({ "chain": "mainnet", "synced": true }))
        }

        async fn best_block(&self) -> Result<Value, String> {
            Ok(json!({ "height": 42 }))
        }

        async fn balance(
            &self,
            account_index: u32,
            utxo_states: Vec<UtxoStateSelector>,
            with_locked: WithLockedSelector,
        ) -> Result<Value, String> {
            if account_index > 3 {
                return Err("no such account".to_owned());
            }
            Ok(json!({
                "account": account_index,
                "states": utxo_states.len(),
                "locked": with_locked == WithLockedSelector::Locked,
                "coin": "100.5"
            }))
        }

        async fn standalone_addresses(&self, account_index: u32) -> Result<Value, String> {
            Ok(json!({ "account": account_index, "addresses": [] }))
        }
    }

    fn request(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
    }

    #[test]
    fn initialize_reports_the_server_identity() {
        let response = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(handle_message(
                &request("initialize", json!({})),
                &StubWallet,
            ))
            .expect("requests are answered");
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(
            response["result"]["serverInfo"]["name"],
            "mintlayer-wallet-mcp"
        );
        assert_eq!(response["result"]["capabilities"]["tools"], json!({}));
    }

    #[test]
    fn tools_are_listed_and_read_only() {
        let response = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(handle_message(
                &request("tools/list", json!({})),
                &StubWallet,
            ))
            .expect("requests are answered");
        let tools = response["result"]["tools"].as_array().expect("tool list");
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            ["version", "wallet_info", "best_block", "balance", "standalone_addresses"]
        );
        // No write-shaped tool may appear in the list.
        assert!(!names.iter().any(|name| {
            name.contains("send") || name.contains("create") || name.contains("sign")
        }));
    }

    #[test]
    fn tool_calls_render_results_as_text_content() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let response = rt
            .block_on(handle_message(
                &request("tools/call", json!({ "name": "wallet_info" })),
                &StubWallet,
            ))
            .expect("requests are answered");
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let rendered: Value = serde_json::from_str(text).unwrap();
        assert_eq!(rendered["chain"], "mainnet");
    }

    #[test]
    fn tool_call_arguments_are_forwarded() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let response = rt.block_on(handle_message(
            &request(
                "tools/call",
                json!({ "name": "balance", "arguments": { "account_index": 2, "utxo_states": ["confirmed", "in-mempool"], "with_locked": "locked" } }),
            ),
            &StubWallet,
        ))
        .expect("requests are answered");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let rendered: Value = serde_json::from_str(text).unwrap();
        assert_eq!(rendered["account"], 2);
        assert_eq!(rendered["states"], 2);
        assert_eq!(rendered["locked"], true);
    }

    #[test]
    fn failing_tools_report_errors_without_breaking_the_protocol() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let response = rt
            .block_on(handle_message(
                &request(
                    "tools/call",
                    json!({ "name": "balance", "arguments": { "account_index": 9 } }),
                ),
                &StubWallet,
            ))
            .expect("requests are answered");
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("no such account")
        );
    }

    #[test]
    fn unknown_tools_and_methods_are_rejected() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let response = rt
            .block_on(handle_message(
                &request("tools/call", json!({ "name": "purge_seed_phrase" })),
                &StubWallet,
            ))
            .expect("requests are answered");
        // Unknown tools are protocol errors, not tool results (MCP spec).
        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["message"].as_str().unwrap().contains("Unknown tool"));

        let response = rt
            .block_on(handle_message(
                &request("wallet/create", json!({})),
                &StubWallet,
            ))
            .expect("requests are answered");
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn requests_with_missing_or_wrong_jsonrpc_version_are_rejected() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        for message in [
            serde_json::json!({ "id": 1, "method": "ping" }),
            serde_json::json!({ "jsonrpc": "1.0", "id": 2, "method": "ping" }),
        ] {
            let response = rt
                .block_on(handle_message(&message, &StubWallet))
                .expect("requests are answered");
            assert_eq!(response["error"]["code"], -32600);
            assert_eq!(response["id"], message["id"]);
        }
    }

    #[test]
    fn notifications_get_no_response_while_malformed_requests_get_an_error() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert_eq!(
            rt.block_on(handle_message(&notification, &StubWallet)),
            None
        );
        let bogus = json!({ "jsonrpc": "2.0", "id": 1 });
        let response =
            rt.block_on(handle_message(&bogus, &StubWallet)).expect("requests are answered");
        assert_eq!(response["error"]["code"], -32600);
    }

    #[test]
    fn null_id_requests_are_answered_with_a_null_id() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let message = json!({ "jsonrpc": "2.0", "id": null, "method": "ping" });
        let response = rt
            .block_on(handle_message(&message, &StubWallet))
            .expect("an explicit null id is a request, not a notification");
        // Indexing with [] maps a missing member to Null, so use get() to
        // prove the id member is present and null.
        assert_eq!(response.get("id"), Some(&Value::Null));
        assert!(response.get("result").is_some());
    }

    #[test]
    fn batched_and_non_object_requests_are_rejected_with_an_error() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        for message in [json!([request("ping", json!({}))]), json!(42)] {
            let response = rt
                .block_on(handle_message(&message, &StubWallet))
                .expect("non-object messages are answered");
            assert_eq!(response["error"]["code"], -32600);
        }
    }

    #[test]
    fn invalid_tool_arguments_are_protocol_errors() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let cases = [
            (
                json!({ "name": "balance", "arguments": { "account_index": "one" } }),
                "account_index",
            ),
            (
                json!({ "name": "balance", "arguments": { "utxo_states": ["bogus"] } }),
                "UTXO state",
            ),
            (
                json!({ "name": "balance", "arguments": { "with_locked": "sometimes" } }),
                "locked filter",
            ),
        ];
        for (params, needle) in cases {
            let message = request("tools/call", params);
            let response = rt
                .block_on(handle_message(&message, &StubWallet))
                .expect("requests are answered");
            assert_eq!(response["error"]["code"], -32602, "for {needle}");
            assert!(response["error"]["message"].as_str().unwrap().contains(needle));
        }
        // A missing tool name is also a protocol error.
        let response = rt
            .block_on(handle_message(
                &request("tools/call", json!({})),
                &StubWallet,
            ))
            .expect("requests are answered");
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn initialize_echoes_only_supported_protocol_versions() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let unsupported = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "1999-01-01" }
        });
        let response = rt
            .block_on(handle_message(&unsupported, &StubWallet))
            .expect("initialize is answered");
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");

        let non_string_version = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": { "protocolVersion": 2024 }
        });
        let response = rt
            .block_on(handle_message(&non_string_version, &StubWallet))
            .expect("initialize is answered");
        assert_eq!(
            response["result"]["protocolVersion"],
            SUPPORTED_PROTOCOL_VERSIONS.last().copied().unwrap()
        );

        let supported = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" }
        });
        let response = rt
            .block_on(handle_message(&supported, &StubWallet))
            .expect("initialize is answered");
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
    }

    #[test]
    fn ping_is_answered_with_an_empty_result() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let response = rt
            .block_on(handle_message(&request("ping", json!({})), &StubWallet))
            .expect("requests are answered");
        assert_eq!(response["result"], json!({}));
    }
}
