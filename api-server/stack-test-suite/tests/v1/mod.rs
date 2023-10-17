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

mod block;
mod block_header;
mod block_reward;
mod block_transaction_ids;
mod chain_at_height;
mod chain_tip;
mod transaction;
mod transaction_merkle_path;

use crate::spawn_webserver;
use api_blockchain_scanner_lib::{
    blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState,
};
use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use api_web_server::{api::web_server, ApiServerWebServerState};
use chainstate::BlockSource;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        config::create_unit_test_config, output_value::OutputValue,
        transaction::output::timelock::OutputTimeLock, Destination, TxOutput,
    },
    primitives::{Amount, BlockHeight, Idable},
};
use hex::ToHex;
use rstest::rstest;
use serde_json::json;
use std::{net::TcpListener, sync::Arc};
use test_utils::random::{make_seedable_rng, Rng, Seed};

#[tokio::test]
async fn chain_genesis() {
    let url = "/api/v1/chain/genesis";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let expected_genesis = chain_config.genesis_block().clone();

                _ = tx.send(expected_genesis);

                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: Arc::clone(&chain_config),
                }
            };

            web_server(listener, web_server_state).await
        }
    });

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let expected_genesis = rx.await.unwrap();

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["block_id"].as_str().unwrap(),
        expected_genesis.get_id().to_hash().encode_hex::<String>()
    );

    task.abort();
}
