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

use std::borrow::Cow;

use common::chain::{
    classic_multisig::ClassicMultisigChallenge,
    htlc::HtlcSecret,
    htlc::{HashedTimelockContract, HtlcSecretHash},
    signature::{
        inputsig::{
            classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
            htlc::{
                produce_classical_multisig_signature_for_htlc_input,
                produce_uniparty_signature_for_htlc_input,
            },
        },
        sighash::signature_hash,
    },
    ChainConfig,
};
use crypto::key::PublicKey;
use serialization::Encode;

use super::*;

fn create_htlc(
    chain_config: &ChainConfig,
    alice_pk: &PublicKey,
    bob_pk: &PublicKey,
    secret_hash: HtlcSecretHash,
) -> (HashedTimelockContract, ClassicMultisigChallenge) {
    let refund_challenge = ClassicMultisigChallenge::new(
        chain_config,
        utils::const_nz_u8!(2),
        vec![alice_pk.clone(), bob_pk.clone()],
    )
    .unwrap();
    let destination_multisig: PublicKeyHash = (&refund_challenge).into();

    let htlc = HashedTimelockContract {
        secret_hash,
        spend_key: Destination::PublicKeyHash(bob_pk.into()),
        refund_timelock: OutputTimeLock::ForBlockCount(0),
        refund_key: Destination::ClassicMultisig(destination_multisig),
    };
    (htlc, refund_challenge)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn spend(#[case] seed: Seed) {
    use api_web_server::api::json_helpers::to_json_string;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);

            let secret = HtlcSecret::new_from_rng(&mut rng);

            let (_, alice_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let (bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // Issue and mint some tokens to lock in htlc
                let issue_and_mint_result =
                    helpers::issue_and_mint_tokens_from_genesis(&mut rng, &mut tf);

                // Create htlc
                let (htlc, _) = create_htlc(&chain_config, &alice_pk, &bob_pk, secret.hash());
                let tx_1 = TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(issue_and_mint_result.tokens_outpoint),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Htlc(
                        OutputValue::TokenV1(
                            issue_and_mint_result.token_id,
                            Amount::from_atoms(100),
                        ),
                        Box::new(htlc),
                    ))
                    .build();
                let tx_1_id = tx_1.transaction().get_id();

                let block1 = tf.make_block_builder().add_transaction(tx_1.clone()).build(&mut rng);
                tf.process_block(block1.clone(), BlockSource::Local).unwrap();

                // Spend htlc
                let tx2 = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_1_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(
                            issue_and_mint_result.token_id,
                            Amount::from_atoms(100),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build()
                    .take_transaction();
                let tx_2_id = tx2.get_id();

                let input_sign = produce_uniparty_signature_for_htlc_input(
                    &bob_sk,
                    SigHashType::all(),
                    Destination::PublicKeyHash((&PublicKey::from_private_key(&bob_sk)).into()),
                    &tx2,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                    secret.clone(),
                    &mut rng,
                )
                .unwrap();

                let block2 = tf
                    .make_block_builder()
                    .add_transaction(
                        SignedTransaction::new(tx2, vec![InputWitness::Standard(input_sign)])
                            .unwrap(),
                    )
                    .build(&mut rng);
                tf.process_block(block2.clone(), BlockSource::Local).unwrap();

                _ = tx.send((
                    block1.get_id().to_hash().encode_hex::<String>(),
                    tx_1_id.to_hash().encode_hex::<String>(),
                    block2.get_id().to_hash().encode_hex::<String>(),
                    tx_2_id.to_hash().encode_hex::<String>(),
                    secret,
                ));

                vec![
                    issue_and_mint_result.issue_block,
                    issue_and_mint_result.mint_block,
                    block1,
                    block2,
                ]
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

        web_server(listener, web_server_state, true).await
    });

    let (block1_id, tx_1_id, block2_id, tx_2_id, secret) = rx.await.unwrap();

    let url = format!("/api/v2/block/{block1_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let url = format!("/api/v2/block/{block2_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let url = format!("/api/v2/transaction/{tx_1_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let url = format!("/api/v2/transaction/{tx_2_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    assert!(body.contains(&format!("\"secret\":{}", to_json_string(secret.secret()))));

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn refund(#[case] seed: Seed) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        let web_server_state = {
            let mut rng = make_seedable_rng(seed);

            let secret = HtlcSecret::new_from_rng(&mut rng);

            let (alice_sk, alice_pk) =
                PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let (bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

            let chain_config = create_unit_test_config();

            let chainstate_blocks = {
                let mut tf = TestFramework::builder(&mut rng)
                    .with_chain_config(chain_config.clone())
                    .build();

                // Create htlc
                let (htlc, refund_challenge) =
                    create_htlc(&chain_config, &alice_pk, &bob_pk, secret.hash());
                let tx_1 = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Htlc(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        Box::new(htlc),
                    ))
                    .build();
                let tx_1_id = tx_1.transaction().get_id();

                let block1 = tf.make_block_builder().add_transaction(tx_1.clone()).build(&mut rng);
                tf.process_block(block1.clone(), BlockSource::Local).unwrap();

                // Spend htlc
                let tx2 = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_1_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build()
                    .take_transaction();

                let authorization = {
                    let mut authorization =
                        AuthorizedClassicalMultisigSpend::new_empty(refund_challenge);

                    let sighash = signature_hash(
                        SigHashType::all(),
                        &tx2,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(
                            &tx_1.transaction().outputs()[0],
                        ))],
                        0,
                    )
                    .unwrap();
                    let sighash = sighash.encode();

                    let signature = alice_sk.sign_message(&sighash, &mut rng).unwrap();
                    authorization.add_signature(0, signature);
                    let signature = bob_sk.sign_message(&sighash, &mut rng).unwrap();
                    authorization.add_signature(1, signature);

                    authorization
                };

                let input_sign = produce_classical_multisig_signature_for_htlc_input(
                    &chain_config,
                    &authorization,
                    SigHashType::all(),
                    &tx2,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                )
                .unwrap();

                let block2 = tf
                    .make_block_builder()
                    .add_transaction(
                        SignedTransaction::new(tx2, vec![InputWitness::Standard(input_sign)])
                            .unwrap(),
                    )
                    .build(&mut rng);
                tf.process_block(block2.clone(), BlockSource::Local).unwrap();

                _ = tx.send((
                    block1.get_id().to_hash().encode_hex::<String>(),
                    block2.get_id().to_hash().encode_hex::<String>(),
                ));

                vec![block1, block2]
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

        web_server(listener, web_server_state, true).await
    });

    let (block1_id, block2_id) = rx.await.unwrap();
    let url = format!("/api/v2/block/{block1_id}");

    // Given that the listener port is open, this will block until a
    // response is made (by the web server, which takes the listener
    // over)
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let url = format!("/api/v2/block/{block2_id}");
    let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    assert!(body.contains("\"secret\":null"));

    task.abort();
}
