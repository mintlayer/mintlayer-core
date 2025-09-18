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

mod address;
mod address_all_utxos;
mod address_delegations;
mod address_spendable_utxos;
mod address_token_authority;
mod block;
mod block_header;
mod block_reward;
mod block_transaction_ids;
mod chain_at_height;
mod chain_tip;
mod feerate;
mod helpers;
mod htlc;
mod nft;
mod orders;
mod pool;
mod pool_block_stats;
mod pools;
mod statistics;
mod token;
mod token_ids;
mod token_ticker;
mod transaction;
mod transaction_merkle_path;
mod transaction_output;
mod transaction_submit;
mod transactions;

use crate::{spawn_webserver, DummyRPC};
use api_blockchain_scanner_lib::{
    blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState,
};
use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use api_web_server::{
    api::{
        json_helpers::{txoutput_to_json, TokenDecimals},
        web_server,
    },
    ApiServerWebServerState, CachedValues,
};
use chainstate::BlockSource;
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    address::{pubkeyhash::PublicKeyHash, Address},
    chain::{
        config::create_unit_test_config,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
        },
        transaction::output::timelock::OutputTimeLock,
        Destination, OutPointSourceId, SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{time::get_time, Amount, BlockHeight, Id, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use hex::ToHex;
use rstest::rstest;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};
use test_utils::random::{make_seedable_rng, Rng, Seed};

#[tokio::test]
async fn chain_genesis() {
    let url = "/api/v2/chain/genesis";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn({
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let expected_genesis = chain_config.genesis_block().clone();

                _ = tx.send(json!({
                    "block_id": expected_genesis.get_id(),
                    "genesis_message": expected_genesis.genesis_message(),
                    "timestamp": expected_genesis.timestamp(),
                    "utxos": expected_genesis.utxos()
                             .iter()
                             .map(|out| txoutput_to_json(out, &chain_config, &TokenDecimals::Single(None)))
                             .collect::<Vec<_>>(),
                }));

                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: Arc::clone(&chain_config),
                    rpc: Arc::new(DummyRPC {}),
                    cached_values: Arc::new(CachedValues {
                        feerate_points: RwLock::new((get_time(), vec![])),
                    }),
                    time_getter: Default::default(),
                }
            };

            web_server(listener, web_server_state, true).await
        }
    });

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    let expected_genesis = rx.await.unwrap();

    assert_eq!(body, expected_genesis);

    task.abort();
}
