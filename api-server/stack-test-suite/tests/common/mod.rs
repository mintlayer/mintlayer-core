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

//! Helpers shared between the test binaries of this crate.
//!
//! Note: this module is linked separately into each test binary, so an item used by only some of
//! the binaries must not be reported as unused; hence the blanket `allow` below.

#![allow(dead_code)]

use api_web_server::TxSubmitClient;
use common::chain::SignedTransaction;
use mempool::FeeRate;
use node_comm::rpc_client::NodeRpcError;

/// A no-op RPC client for the web server state under test.
pub struct DummyRPC {}

#[async_trait::async_trait]
impl TxSubmitClient for DummyRPC {
    async fn submit_tx(&self, _: SignedTransaction) -> Result<(), NodeRpcError> {
        Ok(())
    }

    async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError> {
        Ok(vec![])
    }
}

/// The value of the `event:` field of an SSE frame, if any.
pub fn frame_event_name(frame: &str) -> Option<&str> {
    frame.lines().find_map(|line| line.strip_prefix("event: "))
}

/// The value of the `data:` field of an SSE frame, if any.
pub fn frame_data(frame: &str) -> Option<&str> {
    frame.lines().find_map(|line| line.strip_prefix("data: "))
}
