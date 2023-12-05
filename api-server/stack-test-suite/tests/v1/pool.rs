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

use chainstate_test_framework::empty_witness;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{stakelock::StakePoolData, Block, DelegationId, PoolId, UtxoOutPoint},
    primitives::{per_thousand::PerThousand, H256},
};
use crypto::{
    random::CryptoRng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};

use super::*;

fn prepare_stake_pool(
    stake_pool_outpoint: UtxoOutPoint,
    rng: &mut (impl Rng + CryptoRng),
    available_amount: Amount,
    tf: &mut TestFramework,
) -> (UtxoOutPoint, StakePoolData, PoolId, Block) {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let min_stake_pool_pledge =
        tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
    let amount_to_stake =
        Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));

    let (_, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    let margin_ratio_per_thousand = rng.gen_range(1..=1000);
    let stake_pool_data = StakePoolData::new(
        amount_to_stake,
        Destination::PublicKey(pk),
        vrf_pk,
        Destination::Address(PublicKeyHash::from_low_u64_ne(rng.gen::<u64>())),
        PerThousand::new(margin_ratio_per_thousand).unwrap(),
        Amount::ZERO,
    );
    let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

    let stake_pool_transaction = TransactionBuilder::new()
        .add_input(stake_pool_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data.clone()),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(stake_pool_transaction.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(stake_pool_transaction).build();

    (transfer_outpoint, stake_pool_data, pool_id, block)
}

fn prepare_delegation(
    transfer_outpoint: UtxoOutPoint,
    rng: &mut (impl Rng + CryptoRng),
    pool_id: PoolId,
    available_amount: Amount,
    tf: &mut TestFramework,
) -> (DelegationId, Destination, UtxoOutPoint, Block) {
    let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);
    let (_, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(pk);
    let create_delegation_tx = TransactionBuilder::new()
        .add_input(transfer_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateDelegationId(destination.clone(), pool_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(create_delegation_tx.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(create_delegation_tx).build();

    (delegation_id, destination, transfer_outpoint, block)
}

fn stake_delegation(
    rng: &mut impl Rng,
    available_amount: Amount,
    transfer_outpoint: UtxoOutPoint,
    delegation_id: DelegationId,
    tf: &mut TestFramework,
) -> (Amount, UtxoOutPoint, Block) {
    let amount_to_delegate = Amount::from_atoms(rng.gen_range(1..=available_amount.into_atoms()));
    let stake_tx = TransactionBuilder::new()
        .add_input(transfer_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(stake_tx.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(stake_tx).build();

    (amount_to_delegate, transfer_outpoint, block)
}

#[tokio::test]
async fn invalid_pool_id() {
    let (task, response) = spawn_webserver("/api/v1/pool/invalid-transaction-id").await;

    assert_eq!(response.status(), 400);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Invalid pool Id");

    task.abort();
}

#[tokio::test]
async fn pool_id_not_fund() {
    let pool_id = PoolId::new(H256::zero());
    let chain_config = create_unit_test_config();
    let pool_id = Address::new(&chain_config, &pool_id).unwrap();
    let (task, response) = spawn_webserver(&format! {"/api/v1/pool/{pool_id}"}).await;

    assert_eq!(response.status(), 404);

    let body = response.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(body["error"].as_str().unwrap(), "Stake pool not found");

    task.abort();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ok(#[case] seed: Seed) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

                let stake_pool_outpoint = UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                );
                let mut available_amount = Amount::from_atoms(10000);

                let (_, pools) = (0..rng.gen_range(1..5)).fold(
                    (stake_pool_outpoint, vec![]),
                    |(stake_pool_outpoint, mut pools), _| {
                        if available_amount == Amount::ZERO {
                            return (stake_pool_outpoint, pools);
                        }

                        let (transfer_outpoint, stake_pool_data, pool_id, block) =
                            prepare_stake_pool(
                                stake_pool_outpoint,
                                &mut rng,
                                available_amount,
                                &mut tf,
                            );

                        let (transfer_outpoint, delegations) = (0..rng.gen_range(0..5)).fold(
                            (transfer_outpoint, vec![]),
                            |(transfer_outpoint, mut delegations), _| {
                                if available_amount == Amount::ZERO {
                                    return (transfer_outpoint, delegations);
                                }

                                let (delegation_id, dest, transfer_outpoint, block) =
                                    prepare_delegation(
                                        transfer_outpoint,
                                        &mut rng,
                                        pool_id,
                                        available_amount,
                                        &mut tf,
                                    );

                                let (amount, transfer_outpoint, block2) = stake_delegation(
                                    &mut rng,
                                    available_amount,
                                    transfer_outpoint,
                                    delegation_id,
                                    &mut tf,
                                );
                                available_amount = (available_amount - amount).unwrap();

                                delegations.push((
                                    delegation_id,
                                    amount,
                                    dest,
                                    vec![block, block2],
                                ));
                                (transfer_outpoint, delegations)
                            },
                        );

                        pools.push((pool_id, stake_pool_data, delegations, block));

                        (transfer_outpoint, pools)
                    },
                );

                let mut blocks = vec![];
                for pool in &pools {
                    tf.process_block(pool.3.clone(), BlockSource::Local).unwrap();
                    blocks.push(pool.3.clone());
                    for delegation in &pool.2 {
                        for block in &delegation.3 {
                            tf.process_block(block.clone(), BlockSource::Local).unwrap();
                            blocks.push(block.clone());
                        }
                    }
                }

                _ = tx.send(pools);

                blocks
            };

            let storage = {
                let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                let mut db_tx = storage.transaction_rw().await.unwrap();
                db_tx.initialize_storage(&chain_config).await.unwrap();
                db_tx.commit().await.unwrap();

                storage
            };

            let chain_config = Arc::new(chain_config);
            let mut local_node = BlockchainState::new(Arc::clone(&chain_config), storage);
            local_node.scan_blocks(BlockHeight::new(0), chainstate_blocks).await.unwrap();

            ApiServerWebServerState {
                db: Arc::new(local_node.storage().clone_storage().await),
                chain_config: Arc::clone(&chain_config),
                rpc: None::<std::sync::Arc<DummyRPC>>,
            }
        };

        web_server(listener, web_server_state).await
    });

    let chain_config = create_unit_test_config();
    let pools = rx.await.unwrap();
    for (pool_id, pool_data, delegations, _) in pools {
        let pool_id = Address::new(&chain_config, &pool_id).unwrap();
        let url = format!("/api/v1/pool/{pool_id}");

        // Given that the listener port is open, this will block until a
        // response is made (by the web server, which takes the listener
        // over)
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_object().unwrap();

        let decommission_key = Address::new(&chain_config, pool_data.decommission_key()).unwrap();
        assert_eq!(
            body.get("decommission_destination").unwrap(),
            decommission_key.get(),
        );
        assert_eq!(
            body.get("pledge").unwrap(),
            &serde_json::json!(pool_data.value())
        );

        assert_eq!(
            body.get("margin_ratio_per_thousand").unwrap(),
            &serde_json::json!(pool_data.margin_ratio_per_thousand())
        );

        assert_eq!(
            body.get("cost_per_block").unwrap(),
            &serde_json::json!(pool_data.cost_per_block())
        );

        assert_eq!(
            body.get("vrf_public_key").unwrap(),
            &serde_json::json!(pool_data.vrf_public_key())
        );

        let url = format!("/api/v1/pool/{pool_id}/delegations");
        let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = response.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let body = body.as_array().unwrap();

        assert_eq!(delegations.len(), body.len());
        for delegation in &delegations {
            let delegation_id = Address::new(&chain_config, &delegation.0).unwrap();
            let resp = body
                .iter()
                .find(|d| {
                    d.get("delegation_id").unwrap() == &serde_json::json!(delegation_id.get())
                })
                .unwrap();

            assert_eq!(
                resp.get("delegation_id").unwrap(),
                &serde_json::json!(delegation_id.get())
            );

            assert_eq!(
                resp.get("balance").unwrap(),
                &serde_json::json!(delegation.1)
            );

            let destination = Address::new(&chain_config, &delegation.2).unwrap();
            assert_eq!(resp.get("spend_destination").unwrap(), destination.get());
        }

        for (delegation_id, balance, destination, _) in delegations {
            let delegation_id = Address::new(&chain_config, &delegation_id).unwrap();
            let url = format!("/api/v1/delegation/{delegation_id}");
            let response = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()))
                .await
                .unwrap();

            assert_eq!(response.status(), 200);

            let body = response.text().await.unwrap();
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            let body = body.as_object().unwrap();

            assert_eq!(
                body.get("pool_id").unwrap(),
                &serde_json::json!(pool_id.get())
            );
            assert_eq!(body.get("balance").unwrap(), &serde_json::json!(balance));
            let destination = Address::new(&chain_config, &destination).unwrap();
            assert_eq!(body.get("spend_destination").unwrap(), destination.get());
        }
    }

    task.abort();
}
