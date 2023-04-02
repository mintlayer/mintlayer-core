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

pub mod comm_impl;

use std::sync::atomic::AtomicU64;

use common::{
    chain::{Block, GenBlock},
    primitives::Id,
};
use serialization::hex::HexDecode;
use ureq::serde::de::Error;

#[derive(thiserror::Error, Debug)]
pub enum NodeRpcError {
    #[error("Request error: {0}")]
    RequestError(Box<ureq::Error>),
    #[error("Response error: {0}")]
    JsonResponseError(#[from] serde_json::Error),
    #[error("Response json interpretation error: {0}")]
    ResponseJsonInterpretationError(std::io::Error),
}

pub struct NodeRpcClient {
    host: String,
}

static REQ_ID: AtomicU64 = AtomicU64::new(0);

impl NodeRpcClient {
    pub fn new(address: String, port: u16) -> Self {
        let host = format!("http://{address}:{port}");
        Self { host }
    }

    fn make_request(&self, req_data: serde_json::Value) -> Result<serde_json::Value, NodeRpcError> {
        let resp = ureq::post(self.host.as_str())
            .set("Accepts", "application/json")
            .send_json(req_data)
            .map_err(|e| NodeRpcError::RequestError(Box::new(e)))?;
        let json_response = resp
            .into_json::<serde_json::Value>()
            .map_err(NodeRpcError::ResponseJsonInterpretationError)?;

        Self::error_if_json_error(&json_response)?;

        Ok(json_response)
    }

    /// If the json response contains the error field, return an error.
    fn error_if_json_error(json_response: &serde_json::Value) -> Result<(), NodeRpcError> {
        if let Some(err) = json_response.get("error") {
            return Err(NodeRpcError::JsonResponseError(serde_json::Error::custom(
                err.to_string(),
            )));
        }
        Ok(())
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, NodeRpcError> {
        let block_id_hex = hex::encode(block_id);

        let req_data = ureq::json!({
            "method": "chainstate_get_block",
            "jsonrpc": "2.0",
            "id": REQ_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            "params": ureq::json!({
                "block_id": block_id_hex,
            }),
        });

        let json_response = self.make_request(req_data)?;

        // TODO: deal with expects
        let optional_block_hex = json_response["result"].as_str().expect("Must be string");
        let block = Option::<Block>::hex_decode_all(optional_block_hex).expect("Must be block");
        Ok(block)
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, NodeRpcError> {
        let req_data = ureq::json!({
            "method": "chainstate_get_best_block_id",
            "jsonrpc": "2.0",
            "id": REQ_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            "params": ureq::json!({}),
        });

        let json_response = self.make_request(req_data)?;

        // TODO: deal with expects
        let block_id_hex = json_response["result"].as_str().expect("Must be string");
        let block_id = Id::<GenBlock>::hex_decode_all(block_id_hex).expect("Must be block id");
        Ok(block_id)
    }
}
