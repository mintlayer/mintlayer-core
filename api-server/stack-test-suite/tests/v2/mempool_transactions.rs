// Copyright (c) 2026 RBB S.r.l
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

use chainstate_test_framework::empty_witness;
use common::{chain::UtxoOutPoint, primitives::H256};

use super::*;

async fn get_mempool_transactions_response(
    addr: std::net::SocketAddr,
    query: &str,
) -> reqwest::Response {
    let response = reqwest::get(format!(
        "http://{}:{}/api/v2/mempool/transactions{query}",
        addr.ip(),
        addr.port()
    ))
    .await
    .unwrap();

    assert_eq!(response.status(), 200);

    response
}

async fn get_mempool_transactions(addr: std::net::SocketAddr, query: &str) -> serde_json::Value {
    let response = get_mempool_transactions_response(addr, query).await;

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    body
}

/// The ids of the transactions of the given mempool listing, preserving the
/// order in which they are listed.
fn listed_transaction_ids_in(body: serde_json::Value) -> Vec<String> {
    let array = body
        .as_array()
        .unwrap_or_else(|| panic!("the mempool listing is not an array: {body}"));
    array
        .iter()
        .map(|tx| {
            tx.get("id")
                .unwrap_or_else(|| panic!("a listed transaction is missing the id field: {tx}"))
                .as_str()
                .unwrap_or_else(|| panic!("the id field is not a string: {tx}"))
                .to_owned()
        })
        .collect()
}

/// Return the ids of the transactions listed by the mempool transactions endpoint,
/// preserving the order in which they are listed.
async fn listed_transaction_ids(addr: std::net::SocketAddr, query: &str) -> Vec<String> {
    let body = get_mempool_transactions(addr, query).await;

    listed_transaction_ids_in(body)
}

/// Return the value of the `x-mempool-ordering` response header and the ids of the
/// transactions listed by the mempool transactions endpoint, preserving the order in
/// which they are listed.
async fn listed_transaction_ids_with_ordering(
    addr: std::net::SocketAddr,
    query: &str,
) -> (String, Vec<String>) {
    let response = get_mempool_transactions_response(addr, query).await;

    let ordering = response
        .headers()
        .get("x-mempool-ordering")
        .unwrap_or_else(|| panic!("the x-mempool-ordering header is missing"))
        .to_str()
        .unwrap()
        .to_owned();

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    (ordering, listed_transaction_ids_in(body))
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn submitted_transaction_is_listed(#[case] seed: Seed) {
    let (task, _response, _rpc, addr) = spawn_webserver_with_mempool("/").await;
    let mut rng = make_seedable_rng(seed);

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(&mut rng))),
                0,
            )),
            empty_witness(&mut rng),
        )
        .build();

    let tx_id = submit_transaction(addr, tx).await;

    let body = get_mempool_transactions(addr, "").await;
    let tx_json = body
        .as_array()
        .unwrap_or_else(|| panic!("the mempool listing is not an array: {body}"))
        .first()
        .cloned()
        .expect("the submitted transaction is not listed");

    let ids = listed_transaction_ids_in(body);

    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], tx_id);

    // The block-related fields of a pending transaction are null: the values
    // are not applicable until the transaction is confirmed.
    assert_eq!(tx_json.get("block_id"), Some(&serde_json::Value::Null));
    assert_eq!(tx_json.get("timestamp"), Some(&serde_json::Value::Null));
    assert_eq!(tx_json.get("confirmations"), Some(&serde_json::Value::Null));

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn dependency_ordering_lists_parents_before_children(#[case] seed: Seed) {
    let (task, _response, _rpc, addr) = spawn_webserver_with_mempool("/").await;
    let mut rng = make_seedable_rng(seed);

    // The parent spends an output unknown to this stack; the child spends the first
    // output of the parent, imitating a chain of unconfirmed transactions in the
    // mempool of the node.
    let parent_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(&mut rng))),
                0,
            )),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let parent_id = parent_tx.transaction().get_id();

    let child_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(parent_id),
                0,
            )),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(500)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    // Submit the child first: the mock mempool accepts chains of unconfirmed
    // transactions without validation, so the child spending the unconfirmed
    // output of the parent is accepted before the parent itself is submitted,
    // imitating the out-of-order arrival of the transactions.
    let child_tx_id = submit_transaction(addr, child_tx).await;

    let ids = listed_transaction_ids(addr, "").await;
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], child_tx_id);

    let parent_id_hex = submit_transaction(addr, parent_tx).await;

    // With the default, insertion-based ordering, the child, which was submitted
    // first, must be listed before the parent
    let ids = listed_transaction_ids(addr, "").await;

    assert_eq!(ids.len(), 2);
    let parent_position = ids.iter().position(|id| *id == parent_id_hex).unwrap();
    let child_position = ids.iter().position(|id| *id == child_tx_id).unwrap();

    assert!(child_position < parent_position);

    // The dependency ordering must list the parent before the child
    let ids = listed_transaction_ids(addr, "?order=dependency").await;

    assert_eq!(ids.len(), 2);
    let parent_position = ids.iter().position(|id| *id == parent_id_hex).unwrap();
    let child_position = ids.iter().position(|id| *id == child_tx_id).unwrap();

    assert!(parent_position < child_position);

    shutdown_task(task).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn dependency_ordering_falls_back_without_refetching_the_mempool(#[case] seed: Seed) {
    let (task, _response, rpc, addr) = spawn_webserver_with_mempool("/").await;
    let mut rng = make_seedable_rng(seed);

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(&mut rng))),
                0,
            )),
            empty_witness(&mut rng),
        )
        .build();

    // The same transaction is submitted twice, so the mempool listing contains
    // duplicated ids, which makes the dependency ordering fail.
    let tx_id = submit_transaction(addr, tx.clone()).await;
    submit_transaction(addr, tx).await;

    let (ordering, ids) = listed_transaction_ids_with_ordering(addr, "?order=dependency").await;

    // The listing fell back to the insertion order of the same snapshot.
    assert_eq!(ordering, "insertion");
    assert_eq!(ids, vec![tx_id.clone(), tx_id]);
    // The mempool was fetched exactly once: the fallback did not refetch it.
    assert_eq!(rpc.fetch_count(), 1);

    shutdown_task(task).await;
}

#[tokio::test]
async fn invalid_ordering() {
    let (task, response, _rpc, _addr) =
        spawn_webserver_with_mempool("/api/v2/mempool/transactions?order=garbage").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        body["error"].as_str().unwrap(),
        "Invalid transaction ordering"
    );

    shutdown_task(task).await;
}

#[tokio::test]
async fn empty_mempool_returns_empty_list() {
    let (task, response, _rpc, _addr) =
        spawn_webserver_with_mempool("/api/v2/mempool/transactions").await;

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert!(body.as_array().unwrap().is_empty());

    shutdown_task(task).await;
}
