// Copyright (c) 2025 RBB S.r.l
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

use common::chain::{
    make_token_id,
    tokens::{IsTokenFreezable, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
    AccountNonce,
};

use crate::DummyRPC;

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);
            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // generate addresses

                let (alice_sk, alice_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                let (bob_sk, bob_pk) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let alice_destination = Destination::PublicKeyHash(PublicKeyHash::from(&alice_pk));
                let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));

                let mut remaining = ((chain_config.fungible_token_issuance_fee() * 10).unwrap()
                    + (chain_config.token_change_authority_fee(BlockHeight::new(1)) * 10).unwrap())
                .unwrap();

                let mut alice_token_ids = vec![];
                let mut bob_token_ids = vec![];
                let mut input = TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                let mut input_utxo = tf.genesis().utxos()[0].clone();

                for _ in 0..10 {
                    let (dest, token_ids) = if rng.gen_bool(0.5) {
                        (alice_destination.clone(), &mut alice_token_ids)
                    } else {
                        (bob_destination.clone(), &mut bob_token_ids)
                    };

                    let token_issuance = TokenIssuanceV1 {
                        token_ticker: "XXXX".as_bytes().to_vec(),
                        number_of_decimals: rng.gen_range(1..18),
                        metadata_uri: "http://uri".as_bytes().to_vec(),
                        total_supply: TokenTotalSupply::Unlimited,
                        authority: dest.clone(),
                        is_freezable: IsTokenFreezable::No,
                    };

                    let transaction = TransactionBuilder::new()
                        .add_input(input, InputWitness::NoSignature(None))
                        .add_output(TxOutput::Transfer(
                            OutputValue::Coin(remaining),
                            Destination::AnyoneCanSpend,
                        ))
                        .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                            token_issuance.clone(),
                        ))))
                        .build();

                    let token_id =
                        make_token_id(&chain_config, tf.next_block_height(), transaction.inputs())
                            .unwrap();
                    token_ids.push(token_id);
                    input = TxInput::from_utxo(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        0,
                    );
                    input_utxo = transaction.outputs()[0].clone();
                    remaining = (remaining - chain_config.fungible_token_issuance_fee()).unwrap();

                    tf.make_block_builder()
                        .add_transaction(transaction.clone())
                        .build_and_process(&mut rng)
                        .unwrap()
                        .unwrap();
                }

                let mut token_nonces = BTreeMap::new();

                for _ in 0..10 {
                    // Select a random token_id and transfer authority to the other person
                    let (token_id, dest, dest2, priv_key, token_ids) = if !alice_token_ids
                        .is_empty()
                        && (bob_token_ids.is_empty() || rng.gen_bool(0.5))
                    {
                        (
                            alice_token_ids.remove(rng.gen_range(0..alice_token_ids.len())),
                            alice_destination.clone(),
                            bob_destination.clone(),
                            &alice_sk,
                            &mut bob_token_ids,
                        )
                    } else {
                        (
                            bob_token_ids.remove(rng.gen_range(0..bob_token_ids.len())),
                            bob_destination.clone(),
                            alice_destination.clone(),
                            &bob_sk,
                            &mut alice_token_ids,
                        )
                    };

                    let nonce = token_nonces
                        .entry(token_id)
                        .and_modify(|nonce: &mut AccountNonce| {
                            *nonce = nonce.increment().unwrap();
                        })
                        .or_insert(AccountNonce::new(0));
                    let change_token_authority = TxInput::AccountCommand(
                        *nonce,
                        common::chain::AccountCommand::ChangeTokenAuthority(
                            token_id,
                            dest2.clone(),
                        ),
                    );

                    let transaction = TransactionBuilder::new()
                        .add_input(input, InputWitness::NoSignature(None))
                        .add_input(change_token_authority, InputWitness::NoSignature(None))
                        .add_output(TxOutput::Transfer(
                            OutputValue::Coin(remaining),
                            Destination::AnyoneCanSpend,
                        ))
                        .build();

                    let witness = InputWitness::Standard(
                        StandardInputSignature::produce_uniparty_signature_for_input(
                            priv_key,
                            SigHashType::all(),
                            dest,
                            &transaction,
                            &[Some(&input_utxo), None],
                            0,
                            &mut rng,
                        )
                        .unwrap(),
                    );

                    let transaction = SignedTransaction::new(
                        transaction.transaction().clone(),
                        vec![InputWitness::NoSignature(None), witness],
                    )
                    .unwrap();

                    token_ids.push(token_id);
                    input = TxInput::from_utxo(
                        OutPointSourceId::Transaction(transaction.transaction().get_id()),
                        0,
                    );
                    input_utxo = transaction.outputs()[0].clone();
                    remaining = (remaining
                        - chain_config.token_change_authority_fee(
                            tf.chainstate.get_best_block_height().unwrap(),
                        ))
                    .unwrap();

                    tf.make_block_builder()
                        .add_transaction(transaction.clone())
                        .build_and_process(&mut rng)
                        .unwrap()
                        .unwrap();
                }

                _ = tx
                    .send([(alice_destination, alice_token_ids), (bob_destination, bob_token_ids)]);

                tf.block_indexes
                    .iter()
                    .map(|idx| tf.block(tf.to_chain_block_id(idx.block_id().into())))
                    .collect::<Vec<_>>()
            };

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.reinitialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            let chain_config = Arc::new(chain_config);

            let mut local_node = BlockchainState::new(Arc::clone(&chain_config), storage);
            local_node.scan_genesis(chain_config.genesis_block()).await.unwrap();
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::clone(&chain_config),
                rpc: Arc::new(DummyRPC {}),
                cached_values: Arc::new(CachedValues {
                    feerate_points: RwLock::new((get_time(), vec![])),
                }),
                time_getter: Default::default(),
            }
        };

        web_server(listener, web_server_state, false).await
    });

    let chain_config = create_unit_test_config();
    for (dest, token_ids) in rx.await.unwrap() {
        let dest = Address::new(&chain_config, dest).unwrap();
        let url = format!("/api/v2/address/{dest}/token-authority");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Failed getting token ids");

        let body = response.text().await.unwrap();

        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr_body = body.as_array().unwrap();

        for token_id in token_ids {
            assert!(arr_body.contains(&serde_json::Value::String(
                Address::new(&chain_config, token_id).unwrap().into_string()
            )));
        }
    }

    task.abort();
}
