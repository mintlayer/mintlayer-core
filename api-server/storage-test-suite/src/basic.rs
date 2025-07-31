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

use rand::CryptoRng;
use serialization::extras::non_empty_vec::DataOrNoVec;
use std::{collections::BTreeMap, sync::Arc};

use crate::helpers::make_trial;
use crate::make_test;
use pos_accounting::PoolData;

use api_server_common::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{
        block_aux_data::{BlockAuxData, BlockWithExtraData},
        ApiServerStorage, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
        ApiServerTransactionRw, BlockInfo, CoinOrTokenStatistic, Delegation, FungibleTokenData,
        LockedUtxo, Order, PoolDataWithExtraInfo, TransactionInfo, Transactional, TxAdditionalInfo,
        Utxo, UtxoLock, UtxoWithExtraInfo,
    },
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::Rng;

use chainstate_test_framework::{empty_witness, TestFramework, TransactionBuilder};
use common::{
    address::{pubkeyhash::PublicKeyHash, Address},
    chain::{
        block::timestamp::BlockTimestamp,
        config::create_unit_test_config,
        output_value::OutputValue,
        tokens::{
            IsTokenFreezable, IsTokenFrozen, NftIssuance, NftIssuanceV0, TokenId, TokenTotalSupply,
        },
        AccountNonce, Block, DelegationId, Destination, OrderId, OutPointSourceId, PoolId,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, CoinOrTokenId, Id, Idable, H256},
};
use futures::Future;
use libtest_mimic::Failed;
use test_utils::{
    assert_matches,
    random::{make_seedable_rng, Seed},
};

pub async fn initialization<S, Fut, F: Fn() -> Fut>(
    storage_maker: Arc<F>,
    _seed_maker: Box<dyn Fn() -> Seed + Send>,
) -> Result<(), Failed>
where
    S: ApiServerStorage,
    Fut: Future<Output = S> + Send + 'static,
{
    let mut storage = storage_maker().await;
    let mut tx = storage.transaction_rw().await.unwrap();
    let chain_config = create_unit_test_config();
    tx.reinitialize_storage(&chain_config).await.unwrap();
    tx.commit().await.unwrap();
    let tx = storage.transaction_ro().await.unwrap();
    assert!(tx.is_initialized().await.unwrap());
    Ok(())
}

pub async fn set_get<S, Fut, F>(
    storage_maker: Arc<F>,
    seed_maker: Box<dyn Fn() -> Seed + Send>,
) -> Result<(), Failed>
where
    S: ApiServerStorage,
    Fut: Future<Output = S> + Send + 'static,
    F: Fn() -> Fut,
{
    let seed = seed_maker();

    let mut rng = make_seedable_rng(seed);

    let mut storage = storage_maker().await;
    let mut tx = storage.transaction_rw().await.unwrap();
    let chain_config = create_unit_test_config();
    tx.reinitialize_storage(&chain_config).await.unwrap();
    tx.commit().await.unwrap();

    let db_tx = storage.transaction_ro().await.unwrap();

    let is_initialized = db_tx.is_initialized().await.unwrap();
    assert!(is_initialized);

    let version_option = db_tx.get_storage_version().await.unwrap();
    assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);

    drop(db_tx);

    // TODO: add more tests with different variations of rw/ro transactions, where things are done in different orders

    // Test setting/getting blocks
    let block_id = {
        let mut test_framework = TestFramework::builder(&mut rng).build();
        let chain_config = test_framework.chain_config().clone();
        let mut db_tx = storage.transaction_rw().await.unwrap();

        // should return genesis block id
        let block_aux = db_tx.get_best_block().await.unwrap();
        assert_eq!(block_aux.block_height(), BlockHeight::new(0));
        assert_eq!(block_aux.block_id(), chain_config.genesis_block_id());
        assert_eq!(
            block_aux.block_timestamp(),
            chain_config.genesis_block().timestamp()
        );

        let timestamps = db_tx.get_latest_blocktimestamps().await.unwrap();
        assert_eq!(timestamps, vec![chain_config.genesis_block().timestamp()]);

        {
            let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
            let block = db_tx.get_block(random_block_id).await.unwrap();
            assert!(block.is_none());
        }
        // Create a test framework and blocks

        let genesis_id = chain_config.genesis_block_id();
        let num_blocks = rng.gen_range(10..20);
        test_framework
            .create_chain_return_ids_with_advancing_time(&genesis_id, num_blocks, &mut rng)
            .unwrap();

        let block_id1 =
            test_framework.block_id(1).classify(&chain_config).chain_block_id().unwrap();
        let block1 = test_framework.block(block_id1);
        let block_height = BlockHeight::new(1);
        let block_info1 = BlockInfo {
            block: BlockWithExtraData {
                block: block1.clone(),
                tx_additional_infos: vec![],
            },
            height: Some(block_height),
        };

        {
            let block_id = db_tx.get_block(block_id1).await.unwrap();
            assert!(block_id.is_none());

            let block_id = db_tx.get_main_chain_block_id(block_height).await.unwrap();
            assert!(block_id.is_none());

            let block_with_extras = BlockWithExtraData {
                block: block1.clone(),
                tx_additional_infos: vec![],
            };
            db_tx
                .set_mainchain_block(block_id1, block_height, &block_with_extras)
                .await
                .unwrap();

            let block = db_tx.get_block(block_id1).await.unwrap();
            assert_eq!(block.unwrap(), block_info1);

            let block_id = db_tx.get_main_chain_block_id(block_height).await.unwrap();
            assert_eq!(block_id.unwrap(), block_id1);

            // delete the main chain block
            db_tx
                .del_main_chain_blocks_above_height(block_height.prev_height().unwrap())
                .await
                .unwrap();
            // no main chain block on that height
            let block_id = db_tx.get_main_chain_block_id(block_height).await.unwrap();
            assert!(block_id.is_none());
            // but the block is still there just not on main chain
            let block_info1 = BlockInfo {
                block: BlockWithExtraData {
                    block: block1.clone(),
                    tx_additional_infos: vec![],
                },
                height: None,
            };
            let block = db_tx.get_block(block_id1).await.unwrap();
            assert_eq!(block.unwrap(), block_info1);
        }

        {
            for block_height in 1..num_blocks {
                let block_height = block_height as u64;
                let block_id = test_framework
                    .block_id(block_height)
                    .classify(&chain_config)
                    .chain_block_id()
                    .unwrap();
                let block = test_framework.block(block_id);
                let block_with_extras = BlockWithExtraData {
                    block: block.clone(),
                    tx_additional_infos: vec![],
                };
                db_tx
                    .set_mainchain_block(
                        block_id,
                        BlockHeight::new(block_height),
                        &block_with_extras,
                    )
                    .await
                    .unwrap();
                db_tx
                    .set_block_aux_data(
                        block_id,
                        &BlockAuxData::new(
                            block_id.into(),
                            BlockHeight::new(block_height),
                            block.timestamp(),
                        ),
                    )
                    .await
                    .unwrap();
            }

            let random_height = rng.gen_range(1..3);
            let block_id = test_framework
                .block_id(random_height)
                .classify(&chain_config)
                .chain_block_id()
                .unwrap();
            let block1 = test_framework.block(block_id);
            let random_height2 = rng.gen_range(3..10);
            let block_id2 = test_framework
                .block_id(random_height2)
                .classify(&chain_config)
                .chain_block_id()
                .unwrap();
            let block2 = test_framework.block(block_id2);

            let block1_timestamp = block1.timestamp();
            let block2_timestamp = block2.timestamp();

            let (h1, h2) = db_tx
                .get_block_range_from_time_range((block1_timestamp, block2_timestamp))
                .await
                .unwrap();

            assert_eq!(h1, BlockHeight::new(random_height));
            assert_eq!(h2, BlockHeight::new(random_height2));

            // delete the main chain block
            db_tx
                .del_main_chain_blocks_above_height(block_height.prev_height().unwrap())
                .await
                .unwrap();
        }

        db_tx.commit().await.unwrap();

        {
            // with read only tx reconfirm everything is the same after the commit
            let db_tx = storage.transaction_ro().await.unwrap();
            let block_id = db_tx.get_main_chain_block_id(block_height).await.unwrap();
            assert!(block_id.is_none());

            let block_info1 = BlockInfo {
                block: BlockWithExtraData {
                    block: block1.clone(),
                    tx_additional_infos: vec![],
                },
                height: None,
            };
            let block = db_tx.get_block(block_id1).await.unwrap();
            assert_eq!(block.unwrap(), block_info1);
        }

        block_id1
    };

    // Test setting/getting transactions
    {
        let db_tx = storage.transaction_ro().await.unwrap();

        let random_tx_id: Id<Transaction> = Id::<Transaction>::new(H256::random_using(&mut rng));
        let tx = db_tx.get_transaction(random_tx_id).await.unwrap();
        assert!(tx.is_none());

        let owning_block1 = block_id;
        let tx1: SignedTransaction = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(
                        &mut rng,
                    ))),
                    0,
                )),
                empty_witness(&mut rng),
            )
            .build();
        let tx1_input_utxos = vec![Some(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..100))),
            Destination::AnyoneCanSpend,
        ))];

        // before storage
        let tx_and_block_id = db_tx.get_transaction(tx1.transaction().get_id()).await.unwrap();
        assert!(tx_and_block_id.is_none());

        let last_num = db_tx.get_last_transaction_global_index().await.unwrap();
        assert_eq!(last_num, None);

        drop(db_tx);

        // Set with not existing owning block
        {
            let mut db_tx = storage.transaction_rw().await.unwrap();

            let tx_info = TransactionInfo {
                tx: tx1.clone(),
                additional_info: TxAdditionalInfo {
                    fee: Amount::from_atoms(rng.gen_range(0..100)),
                    input_utxos: tx1_input_utxos.clone(),
                    token_decimals: BTreeMap::new(),
                },
            };
            let random_owning_block = Id::<Block>::new(H256::random_using(&mut rng));
            let result = db_tx
                .set_transaction(tx1.transaction().get_id(), 1, random_owning_block, &tx_info)
                .await
                .unwrap_err();

            assert_matches!(result, ApiServerStorageError::LowLevelStorageError(..));
        }

        let mut db_tx = storage.transaction_rw().await.unwrap();

        // Set with owning block
        {
            let tx_info = TransactionInfo {
                tx: tx1.clone(),
                additional_info: TxAdditionalInfo {
                    fee: Amount::from_atoms(rng.gen_range(0..100)),
                    input_utxos: tx1_input_utxos.clone(),
                    token_decimals: BTreeMap::new(),
                },
            };
            db_tx
                .set_transaction(tx1.transaction().get_id(), 2, owning_block1, &tx_info)
                .await
                .unwrap();

            let tx_and_block_id = db_tx.get_transaction(tx1.transaction().get_id()).await.unwrap();
            assert!(tx_and_block_id.is_some());

            let (owning_block, tx_retrieved) = tx_and_block_id.unwrap();
            assert_eq!(owning_block, owning_block1);
            assert_eq!(tx_retrieved, tx_info);
        }

        db_tx.commit().await.unwrap();

        let mut db_tx = storage.transaction_rw().await.unwrap();
        {
            let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height1 = height1_u64.into();
            let random_block_timestamp = BlockTimestamp::from_int_seconds(rng.gen::<u64>());
            let aux_data1 =
                BlockAuxData::new(owning_block1.into(), height1, random_block_timestamp);
            db_tx.set_block_aux_data(owning_block1, &aux_data1).await.unwrap();

            let tx_info = TransactionInfo {
                tx: tx1.clone(),
                additional_info: TxAdditionalInfo {
                    fee: Amount::from_atoms(rng.gen_range(0..100)),
                    input_utxos: tx1_input_utxos.clone(),
                    token_decimals: BTreeMap::new(),
                },
            };

            let expected_last_tx_global_index = 20;
            let start_tx_global_index = 10;
            for i in start_tx_global_index..=expected_last_tx_global_index {
                let tx_id = H256::random_using(&mut rng);
                db_tx.set_transaction(tx_id.into(), i, owning_block1, &tx_info).await.unwrap();
            }

            let last_num = db_tx.get_last_transaction_global_index().await.unwrap();
            assert_eq!(last_num, Some(expected_last_tx_global_index));

            let take_txs = rng.gen_range(1..expected_last_tx_global_index - start_tx_global_index);
            let txs = db_tx
                .get_transactions_with_block_info_before_tx_global_index(
                    take_txs as u32,
                    last_num.unwrap() + 1,
                )
                .await
                .unwrap();
            assert_eq!(txs.len() as u64, take_txs);
            for (i, tx) in txs.iter().enumerate() {
                assert_eq!(tx.global_tx_index, expected_last_tx_global_index - i as u64);
            }
        }

        db_tx.rollback().await.unwrap();
    }

    // Test setting/getting block aux data
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
        let random_block_timestamp = BlockTimestamp::from_int_seconds(rng.gen::<u64>());
        let block = db_tx.get_block_aux_data(random_block_id).await.unwrap();
        assert!(block.is_none());

        let existing_block_id: Id<Block> = block_id;
        let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height1 = height1_u64.into();
        let aux_data1 =
            BlockAuxData::new(existing_block_id.into(), height1, random_block_timestamp);
        db_tx.set_block_aux_data(existing_block_id, &aux_data1).await.unwrap();

        let retrieved_aux_data = db_tx.get_block_aux_data(existing_block_id).await.unwrap();
        assert_eq!(retrieved_aux_data, Some(aux_data1));

        // Test overwrite
        let height2_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height2 = height2_u64.into();
        let random_block_timestamp = BlockTimestamp::from_int_seconds(rng.gen::<u64>());
        let aux_data2 =
            BlockAuxData::new(existing_block_id.into(), height2, random_block_timestamp);
        db_tx.set_block_aux_data(existing_block_id, &aux_data2).await.unwrap();

        let retrieved_aux_data = db_tx.get_block_aux_data(existing_block_id).await.unwrap();
        assert_eq!(retrieved_aux_data, Some(aux_data2));

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting address spendable utxos
    {
        let db_tx = storage.transaction_ro().await.unwrap();
        let test_framework = TestFramework::builder(&mut rng).build();
        let chain_config = test_framework.chain_config().clone();

        let (_bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
        let bob_address =
            Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();

        let tx = db_tx.get_address_available_utxos(bob_address.as_str()).await.unwrap();
        assert!(tx.is_empty());

        drop(db_tx);

        let mut db_tx = storage.transaction_rw().await.unwrap();

        let random_tx_id: Id<Transaction> = Id::<Transaction>::new(H256::random_using(&mut rng));
        let outpoint = UtxoOutPoint::new(
            OutPointSourceId::Transaction(random_tx_id),
            rng.gen::<u32>(),
        );
        let output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..1000))),
            bob_destination.clone(),
        );

        let utxo = Utxo::new(output.clone(), None, false);
        let block_height = BlockHeight::new(rng.gen_range(1..100));

        // set one and get it
        {
            let locked_utxo = LockedUtxo::new(
                output.clone(),
                None,
                UtxoLock::UntilHeight(block_height.next_height()),
            );
            db_tx
                .set_locked_utxo_at_height(
                    outpoint.clone(),
                    locked_utxo,
                    bob_address.as_str(),
                    block_height,
                )
                .await
                .unwrap();

            let block_timestamp = BlockTimestamp::from_int_seconds(0);
            let bob_utxos = db_tx
                .get_locked_utxos_until_now(block_height, (block_timestamp, block_timestamp))
                .await
                .unwrap();
            assert!(bob_utxos.is_empty());

            let bob_utxos = db_tx
                .get_locked_utxos_until_now(
                    block_height.next_height(),
                    (block_timestamp, block_timestamp),
                )
                .await
                .unwrap();
            assert_eq!(
                bob_utxos,
                vec![(
                    outpoint.clone(),
                    UtxoWithExtraInfo::new(output.clone(), None),
                )]
            );

            db_tx
                .del_locked_utxo_above_height(block_height.prev_height().unwrap())
                .await
                .unwrap();

            let next_block_timestamp = block_timestamp.add_int_seconds(10).unwrap();
            let locked_utxo = LockedUtxo::new(
                output.clone(),
                None,
                UtxoLock::UntilTime(next_block_timestamp),
            );
            db_tx
                .set_locked_utxo_at_height(
                    outpoint.clone(),
                    locked_utxo,
                    bob_address.as_str(),
                    block_height,
                )
                .await
                .unwrap();

            let bob_utxos = db_tx
                .get_locked_utxos_until_now(block_height, (block_timestamp, block_timestamp))
                .await
                .unwrap();
            assert!(bob_utxos.is_empty());

            let bob_utxos = db_tx
                .get_locked_utxos_until_now(
                    block_height.next_height(),
                    (block_timestamp, next_block_timestamp),
                )
                .await
                .unwrap();
            assert_eq!(
                bob_utxos,
                vec![(
                    outpoint.clone(),
                    UtxoWithExtraInfo::new(output.clone(), None),
                )]
            );

            let bob_utxos = db_tx
                .get_locked_utxos_until_now(
                    block_height.next_height(),
                    (
                        next_block_timestamp,
                        next_block_timestamp.add_int_seconds(10).unwrap(),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(bob_utxos, vec![]);
        }

        // get all utxos
        {
            // some new address
            let (_bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

            let bob_destination = Destination::PublicKeyHash(PublicKeyHash::from(&bob_pk));
            let bob_address =
                Address::<Destination>::new(&chain_config, bob_destination.clone()).unwrap();

            let random_tx_id: Id<Transaction> =
                Id::<Transaction>::new(H256::random_using(&mut rng));
            let outpoint = UtxoOutPoint::new(
                OutPointSourceId::Transaction(random_tx_id),
                rng.gen::<u32>(),
            );
            let output = TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..1000))),
                bob_destination.clone(),
            );

            // setup a locked utxo
            let locked_utxo = LockedUtxo::new(
                output.clone(),
                None,
                UtxoLock::UntilHeight(block_height.next_height()),
            );
            db_tx
                .set_locked_utxo_at_height(
                    outpoint.clone(),
                    locked_utxo,
                    bob_address.as_str(),
                    block_height,
                )
                .await
                .unwrap();

            // set it as unlocked at next block height
            let utxo = Utxo::new(output.clone(), None, false);
            db_tx
                .set_utxo_at_height(
                    outpoint.clone(),
                    utxo,
                    bob_address.as_str(),
                    block_height.next_height(),
                )
                .await
                .unwrap();

            // and set it as spent on the next block height
            let spent_utxo = Utxo::new(output.clone(), None, true);
            db_tx
                .set_utxo_at_height(
                    outpoint.clone(),
                    spent_utxo,
                    bob_address.as_str(),
                    block_height.next_height().next_height(),
                )
                .await
                .unwrap();

            // set another locked utxo
            let random_tx_id: Id<Transaction> =
                Id::<Transaction>::new(H256::random_using(&mut rng));
            let locked_outpoint = UtxoOutPoint::new(
                OutPointSourceId::Transaction(random_tx_id),
                rng.gen::<u32>(),
            );
            let locked_output = TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..1000))),
                bob_destination.clone(),
            );

            let locked_utxo = LockedUtxo::new(
                locked_output.clone(),
                None,
                UtxoLock::UntilHeight(BlockHeight::new(rng.gen_range(10000..100000))),
            );
            db_tx
                .set_locked_utxo_at_height(
                    locked_outpoint.clone(),
                    locked_utxo,
                    bob_address.as_str(),
                    block_height,
                )
                .await
                .unwrap();

            // should return only the locked utxo as the other one is spent
            let utxos = db_tx.get_address_all_utxos(bob_address.as_str()).await.unwrap();
            assert_eq!(utxos.len(), 1);
            assert_eq!(utxos.iter().find(|utxo| utxo.0 == outpoint), None,);
            assert_eq!(
                utxos.iter().find(|utxo| utxo.0 == locked_outpoint),
                Some(&(locked_outpoint, UtxoWithExtraInfo::new(locked_output, None)))
            );
        }

        // set one and get it
        {
            db_tx
                .set_utxo_at_height(outpoint.clone(), utxo, bob_address.as_str(), block_height)
                .await
                .unwrap();

            let bob_utxos = db_tx.get_address_available_utxos(bob_address.as_str()).await.unwrap();
            assert_eq!(
                bob_utxos,
                vec![(
                    outpoint.clone(),
                    UtxoWithExtraInfo::new(output.clone(), None)
                )]
            );
        }

        // set another one and retrieve both
        {
            let random_tx_id: Id<Transaction> =
                Id::<Transaction>::new(H256::random_using(&mut rng));
            let outpoint2 = UtxoOutPoint::new(
                OutPointSourceId::Transaction(random_tx_id),
                rng.gen::<u32>(),
            );
            let output2 = TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..1000))),
                bob_destination,
            );

            let utxo = Utxo::new(output2.clone(), None, false);
            let block_height = BlockHeight::new(rng.gen_range(1..100));
            db_tx
                .set_utxo_at_height(
                    outpoint2.clone(),
                    utxo.clone(),
                    bob_address.as_str(),
                    block_height,
                )
                .await
                .unwrap();

            let bob_utxos = db_tx.get_address_available_utxos(bob_address.as_str()).await.unwrap();
            let mut expected_utxos = BTreeMap::from_iter([
                (outpoint, UtxoWithExtraInfo::new(output, None)),
                (
                    outpoint2.clone(),
                    UtxoWithExtraInfo::new(output2.clone(), None),
                ),
            ]);
            assert_eq!(bob_utxos.len(), 2);

            for (outpoint, output) in bob_utxos {
                let expected = expected_utxos.get(&outpoint).unwrap();
                assert_eq!(&output, expected);
            }

            // set the new one to spent in the same block
            let utxo = Utxo::new(output2.clone(), None, true);
            expected_utxos.remove(&outpoint2);
            db_tx
                .set_utxo_at_height(outpoint2, utxo, bob_address.as_str(), block_height)
                .await
                .unwrap();

            let bob_utxos = db_tx.get_address_available_utxos(bob_address.as_str()).await.unwrap();
            assert_eq!(bob_utxos.len(), 1);

            for (outpoint, output) in bob_utxos {
                let expected = expected_utxos.get(&outpoint).unwrap();
                assert_eq!(&output, expected);
            }
        }

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting pool data
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        // test missing random pool data
        {
            let random_pool_id = PoolId::new(H256::random_using(&mut rng));
            let pool_data = db_tx.get_pool_data(random_pool_id).await.unwrap();
            assert!(pool_data.is_none());

            let pools = db_tx.get_latest_pool_data(1, 0).await.unwrap();
            assert!(pools.is_empty());

            let pools = db_tx.get_pool_data_with_largest_staker_balance(1, 0).await.unwrap();
            assert!(pools.is_empty());
        }

        {
            let random_pool_id = PoolId::new(H256::random_using(&mut rng));
            let random_block_height = BlockHeight::new(rng.gen::<u32>() as u64);
            let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let amount_to_stake = Amount::from_atoms(rng.gen::<u128>());
            let cost_per_block = Amount::from_atoms(rng.gen::<u128>());

            let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

            let margin_ratio_per_thousand = rng.gen_range(1..=1000);
            let random_pool_data = PoolData::new(
                Destination::PublicKey(pk),
                amount_to_stake,
                Amount::ZERO,
                vrf_pk,
                PerThousand::new(margin_ratio_per_thousand).unwrap(),
                cost_per_block,
            );
            let random_pool_data = PoolDataWithExtraInfo {
                pool_data: random_pool_data,
                delegations_balance: Amount::from_atoms(rng.gen_range(0..=1000)),
            };

            db_tx
                .set_pool_data_at_height(random_pool_id, &random_pool_data, random_block_height)
                .await
                .unwrap();

            let pool_data = db_tx.get_pool_data(random_pool_id).await.unwrap().unwrap();
            assert_eq!(pool_data, random_pool_data);

            // insert a second pool data
            let random_pool_id2 = PoolId::new(H256::random_using(&mut rng));
            let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let amount_to_stake = {
                let mut amount_to_stake = Amount::from_atoms(rng.gen::<u128>());
                while amount_to_stake == random_pool_data.staker_balance().unwrap() {
                    amount_to_stake = Amount::from_atoms(rng.gen::<u128>());
                }
                amount_to_stake
            };
            let cost_per_block = Amount::from_atoms(rng.gen::<u128>());
            let margin_ratio_per_thousand = rng.gen_range(1..=1000);
            let random_pool_data2 = PoolData::new(
                Destination::PublicKey(pk),
                amount_to_stake,
                Amount::ZERO,
                vrf_pk,
                PerThousand::new(margin_ratio_per_thousand).unwrap(),
                cost_per_block,
            );
            let random_block_height2 = {
                let mut height = BlockHeight::new(rng.gen::<u32>() as u64);
                while height == random_block_height {
                    height = BlockHeight::new(rng.gen::<u32>() as u64)
                }
                height
            };
            let random_pool_data2 = PoolDataWithExtraInfo {
                pool_data: random_pool_data2,
                delegations_balance: Amount::from_atoms(rng.gen_range(0..=1000)),
            };

            db_tx
                .set_pool_data_at_height(random_pool_id2, &random_pool_data2, random_block_height2)
                .await
                .unwrap();

            let pool_data = db_tx.get_pool_data(random_pool_id2).await.unwrap().unwrap();
            assert_eq!(pool_data, random_pool_data2);

            // check getting by latest pool
            let expected_latest_pool_data = if random_block_height > random_block_height2 {
                (random_pool_id, &random_pool_data)
            } else {
                (random_pool_id2, &random_pool_data2)
            };

            let latest_pool_data = db_tx.get_latest_pool_data(1, 0).await.unwrap();
            assert_eq!(latest_pool_data.len(), 1);
            let (latest_pool_id, latest_pool_data) = latest_pool_data.last().unwrap();
            assert_eq!(*latest_pool_id, expected_latest_pool_data.0);
            assert_eq!(latest_pool_data, expected_latest_pool_data.1);

            // check getting by pledge amount
            let expected_pool_data_largest_pledge = if random_pool_data.staker_balance().unwrap()
                > random_pool_data2.staker_balance().unwrap()
            {
                (random_pool_id, &random_pool_data)
            } else {
                (random_pool_id2, &random_pool_data2)
            };

            let latest_pool_data =
                db_tx.get_pool_data_with_largest_staker_balance(1, 0).await.unwrap();
            assert_eq!(latest_pool_data.len(), 1);
            let (latest_pool_id, latest_pool_data) = latest_pool_data.last().unwrap();
            assert_eq!(*latest_pool_id, expected_pool_data_largest_pledge.0);
            assert_eq!(latest_pool_data, expected_pool_data_largest_pledge.1);

            // update the first one
            let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let amount_to_stake = Amount::from_atoms(rng.gen::<u128>());
            let cost_per_block = Amount::from_atoms(rng.gen::<u128>());
            let margin_ratio_per_thousand = rng.gen_range(1..=1000);
            let random_pool_data_new = PoolData::new(
                Destination::PublicKey(pk.clone()),
                amount_to_stake,
                Amount::ZERO,
                vrf_pk.clone(),
                PerThousand::new(margin_ratio_per_thousand).unwrap(),
                cost_per_block,
            );
            let random_pool_data_new = PoolDataWithExtraInfo {
                pool_data: random_pool_data_new,
                delegations_balance: Amount::from_atoms(rng.gen_range(0..=1000)),
            };

            // update pool data in next block height
            db_tx
                .set_pool_data_at_height(
                    random_pool_id,
                    &random_pool_data_new,
                    random_block_height.next_height(),
                )
                .await
                .unwrap();

            let pool_data = db_tx.get_pool_data(random_pool_id).await.unwrap().unwrap();
            assert_eq!(pool_data, random_pool_data_new);

            let block_count = db_tx
                .get_pool_block_stats(
                    random_pool_id,
                    (
                        random_block_height,
                        random_block_height.next_height().next_height(),
                    ),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(block_count.block_count, 1);

            // delete the new data
            db_tx.del_pools_above_height(random_block_height).await.unwrap();

            // the old data should still be there
            let pool_data = db_tx.get_pool_data(random_pool_id).await.unwrap().unwrap();
            assert_eq!(pool_data, random_pool_data);

            // decommission one of the pools
            let decommissioned_random_pool_data = PoolData::new(
                Destination::PublicKey(pk),
                Amount::ZERO,
                Amount::ZERO,
                vrf_pk,
                PerThousand::new(margin_ratio_per_thousand).unwrap(),
                cost_per_block,
            );
            let decommissioned_random_pool_data = PoolDataWithExtraInfo {
                pool_data: decommissioned_random_pool_data,
                delegations_balance: Amount::from_atoms(rng.gen_range(0..=1000)),
            };
            eprintln!("setting pledge to 0 for pool {random_pool_id:?}");
            db_tx
                .set_pool_data_at_height(
                    random_pool_id,
                    &decommissioned_random_pool_data,
                    random_block_height.next_height().next_height(),
                )
                .await
                .unwrap();

            if random_block_height2 < random_block_height {
                let latest_pool_data = db_tx.get_latest_pool_data(2, 0).await.unwrap();
                assert_eq!(latest_pool_data.len(), 1);
                let (latest_pool_id, latest_pool_data) = latest_pool_data.last().unwrap();
                assert_eq!(*latest_pool_id, random_pool_id2);
                assert_eq!(latest_pool_data, &random_pool_data2);

                let latest_pool_data =
                    db_tx.get_pool_data_with_largest_staker_balance(2, 0).await.unwrap();
                assert_eq!(latest_pool_data.len(), 1);
                let (latest_pool_id, latest_pool_data) = latest_pool_data.last().unwrap();
                assert_eq!(*latest_pool_id, random_pool_id2);
                assert_eq!(latest_pool_data, &random_pool_data2);
            } else {
                let latest_pool_data = db_tx.get_latest_pool_data(2, 0).await.unwrap();
                assert_eq!(latest_pool_data.len(), 0);
                let latest_pool_data =
                    db_tx.get_pool_data_with_largest_staker_balance(2, 0).await.unwrap();
                assert_eq!(latest_pool_data.len(), 0);
            }
        }

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting delegation data
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        // test missing random pool data
        {
            let random_delegation_id = DelegationId::new(H256::random_using(&mut rng));
            let delegation_data = db_tx.get_delegation(random_delegation_id).await.unwrap();
            assert!(delegation_data.is_none());
        }

        {
            let (random_delegation_id, random_delegation_id2) = {
                let id1 = DelegationId::new(H256::random_using(&mut rng));
                let id2 = DelegationId::new(H256::random_using(&mut rng));

                if id1 < id2 {
                    (id1, id2)
                } else {
                    (id2, id1)
                }
            };

            let random_block_height = BlockHeight::new(rng.gen_range(500..1000) as u64);
            let random_block_height2 = BlockHeight::new(rng.gen_range(1..500) as u64);

            let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let random_pool_id = PoolId::new(H256::random_using(&mut rng));
            let random_pool_id2 = PoolId::new(H256::random_using(&mut rng));
            let random_balance = Amount::from_atoms(rng.gen::<u128>());
            let random_balance2 = Amount::from_atoms(rng.gen::<u128>());
            let random_nonce = AccountNonce::new(rng.gen::<u64>());
            let random_nonce2 = AccountNonce::new(rng.gen::<u64>());

            let random_delegation = Delegation::new(
                random_block_height,
                Destination::PublicKey(pk.clone()),
                random_pool_id,
                random_balance,
                random_nonce,
            );

            let random_delegation2 = Delegation::new(
                random_block_height2,
                Destination::PublicKey(pk.clone()),
                random_pool_id2,
                random_balance2,
                random_nonce2,
            );

            db_tx
                .set_delegation_at_height(
                    random_delegation_id,
                    &random_delegation,
                    random_block_height,
                )
                .await
                .unwrap();
            db_tx
                .set_delegation_at_height(
                    random_delegation_id2,
                    &random_delegation2,
                    random_block_height2,
                )
                .await
                .unwrap();

            let delegation = db_tx.get_delegation(random_delegation_id).await.unwrap().unwrap();
            assert_eq!(delegation, random_delegation);

            let delegations = db_tx.get_pool_delegations(random_pool_id).await.unwrap();
            assert_eq!(delegations.len(), 1);
            assert_eq!(delegations.values().last().unwrap(), &random_delegation);

            let mut delegations = db_tx
                .get_delegations_from_address(random_delegation.spend_destination())
                .await
                .unwrap();
            delegations.sort_by_key(|(id, _)| *id);
            assert_eq!(delegations.len(), 2);

            let (delegation_id, delegation) = delegations.first().unwrap();
            assert_eq!(delegation_id, &random_delegation_id);
            assert_eq!(delegation, &random_delegation);
            let (delegation_id, delegation) = delegations.last().unwrap();
            assert_eq!(delegation_id, &random_delegation_id2);
            assert_eq!(delegation, &random_delegation2);

            // update delegation on new height
            let random_balance = Amount::from_atoms(rng.gen::<u128>());
            let random_nonce = AccountNonce::new(rng.gen::<u64>());

            let random_delegation_new = Delegation::new(
                random_block_height,
                Destination::PublicKey(pk),
                random_pool_id,
                random_balance,
                random_nonce,
            );

            db_tx
                .set_delegation_at_height(
                    random_delegation_id,
                    &random_delegation_new,
                    random_block_height.next_height(),
                )
                .await
                .unwrap();

            let delegation = db_tx.get_delegation(random_delegation_id).await.unwrap().unwrap();
            assert_eq!(delegation, random_delegation_new);

            let delegations = db_tx.get_pool_delegations(random_pool_id).await.unwrap();
            assert_eq!(delegations.len(), 1);
            assert_eq!(delegations.values().last().unwrap(), &random_delegation_new);

            let mut delegations = db_tx
                .get_delegations_from_address(random_delegation.spend_destination())
                .await
                .unwrap();
            delegations.sort_by_key(|(id, _)| *id);
            assert_eq!(delegations.len(), 2);

            let (delegation_id, delegation) = delegations.first().unwrap();
            assert_eq!(delegation_id, &random_delegation_id);
            assert_eq!(delegation, &random_delegation_new);
            let (delegation_id, delegation) = delegations.last().unwrap();
            assert_eq!(delegation_id, &random_delegation_id2);
            assert_eq!(delegation, &random_delegation2);

            // delete the new one and we should be back to the old one
            db_tx.del_delegations_above_height(random_block_height).await.unwrap();
            let delegation = db_tx.get_delegation(random_delegation_id).await.unwrap().unwrap();
            assert_eq!(delegation, random_delegation);

            let delegations = db_tx.get_pool_delegations(random_pool_id).await.unwrap();
            assert_eq!(delegations.len(), 1);
            assert_eq!(delegations.values().last().unwrap(), &random_delegation);

            let mut delegations = db_tx
                .get_delegations_from_address(random_delegation.spend_destination())
                .await
                .unwrap();
            delegations.sort_by_key(|(id, _)| *id);
            assert_eq!(delegations.len(), 2);

            let (delegation_id, delegation) = delegations.first().unwrap();
            assert_eq!(delegation_id, &random_delegation_id);
            assert_eq!(delegation, &random_delegation);
            let (delegation_id, delegation) = delegations.last().unwrap();
            assert_eq!(delegation_id, &random_delegation_id2);
            assert_eq!(delegation, &random_delegation2);

            db_tx
                .del_delegations_above_height(random_block_height.prev_height().unwrap())
                .await
                .unwrap();
            let delegation = db_tx.get_delegation(random_delegation_id).await.unwrap();
            assert!(delegation.is_none());
        }

        db_tx.commit().await.unwrap();
    }

    // test nfts
    {
        let db_tx = storage.transaction_ro().await.unwrap();

        let random_token_id = TokenId::new(H256::random_using(&mut rng));
        let nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap();
        assert!(nft.is_none());

        drop(db_tx);

        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let random_owner = Destination::PublicKeyHash(PublicKeyHash::from(&pk));
        let nft = NftIssuance::V0(NftIssuanceV0 {
            metadata: common::chain::tokens::Metadata {
                creator: None,
                name: "Name".as_bytes().to_vec(),
                description: "SomeNFT".as_bytes().to_vec(),
                ticker: "XXXX".as_bytes().to_vec(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: "123456".as_bytes().to_vec(),
            },
        });

        let mut db_tx = storage.transaction_rw().await.unwrap();

        let block_height = BlockHeight::new(rng.gen_range(1..100));
        db_tx
            .set_nft_token_issuance(random_token_id, block_height, nft.clone(), &random_owner)
            .await
            .unwrap();

        let returned_nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_nft.nft, nft);
        assert_eq!(returned_nft.owner.unwrap(), random_owner);

        // Spend the nft
        let address = Address::new(&chain_config, random_owner).unwrap();
        db_tx
            .set_address_balance_at_height(
                &address,
                Amount::ZERO,
                CoinOrTokenId::TokenId(random_token_id),
                block_height.next_height(),
            )
            .await
            .unwrap();

        let returned_nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_nft.nft, nft);
        // now owner is None
        assert_eq!(returned_nft.owner, None);

        // Send the nft to a new owner
        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let random_owner2 = Destination::PublicKeyHash(PublicKeyHash::from(&pk));
        let address2 = Address::new(&chain_config, random_owner2).unwrap();
        db_tx
            .set_address_balance_at_height(
                &address2,
                Amount::from_atoms(1),
                CoinOrTokenId::TokenId(random_token_id),
                block_height.next_height(),
            )
            .await
            .unwrap();

        let balances = db_tx.get_address_balances(address2.as_str()).await.unwrap();
        assert_eq!(balances.len(), 1);
        let balance = balances.into_iter().next().unwrap();
        assert_eq!(balance.0, CoinOrTokenId::TokenId(random_token_id));
        assert_eq!(balance.1.amount, Amount::from_atoms(1));
        assert_eq!(balance.1.decimals, 0);

        let returned_nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_nft.nft, nft);
        // now owner is the new owner
        assert_eq!(&returned_nft.owner.unwrap(), address2.as_object());

        // delete the latest block height
        db_tx.del_nft_issuance_above_height(block_height).await.unwrap();

        let returned_nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap().unwrap();
        assert_eq!(returned_nft.nft, nft);
        // now owner is the old owner again
        assert_eq!(&returned_nft.owner.unwrap(), address.as_object());

        db_tx
            .del_nft_issuance_above_height(block_height.prev_height().unwrap())
            .await
            .unwrap();

        let nft = db_tx.get_nft_token_issuance(random_token_id).await.unwrap();
        assert!(nft.is_none());

        db_tx.commit().await.unwrap();
    }

    // test tokens
    {
        let db_tx = storage.transaction_ro().await.unwrap();

        let random_token_id = TokenId::new(H256::random_using(&mut rng));
        let token = db_tx.get_fungible_token_issuance(random_token_id).await.unwrap();
        assert!(token.is_none());

        drop(db_tx);

        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let random_destination = Destination::PublicKeyHash(PublicKeyHash::from(&pk));
        let random_num_decimals = rng.gen_range(1..18);

        let token_data = FungibleTokenData {
            token_ticker: "XXXX".as_bytes().to_vec(),
            number_of_decimals: random_num_decimals,
            metadata_uri: "http://uri".as_bytes().to_vec(),
            circulating_supply: Amount::ZERO,
            total_supply: TokenTotalSupply::Unlimited,
            is_locked: false,
            frozen: IsTokenFrozen::No(IsTokenFreezable::Yes),
            authority: random_destination.clone(),
            next_nonce: AccountNonce::new(0),
        };

        let mut db_tx = storage.transaction_rw().await.unwrap();

        let block_height = BlockHeight::new(rng.gen_range(1..100));
        db_tx
            .set_fungible_token_issuance(random_token_id, block_height, token_data.clone())
            .await
            .unwrap();

        let returned_token =
            db_tx.get_fungible_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_token, token_data);

        let tokens = db_tx
            .get_fungible_tokens_by_authority(random_destination.clone())
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], random_token_id);

        let locked_token_data = token_data
            .clone()
            .mint_tokens(
                Amount::from_atoms(rng.gen_range(1..1000)),
                token_data.next_nonce,
            )
            .lock(token_data.next_nonce.increment().unwrap());

        db_tx
            .set_fungible_token_data(
                random_token_id,
                block_height.next_height(),
                locked_token_data.clone(),
            )
            .await
            .unwrap();

        let returned_token =
            db_tx.get_fungible_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_token, locked_token_data);

        let address = Address::new(&chain_config, random_destination.clone()).unwrap();
        let random_amount = Amount::from_atoms(rng.gen_range(0..100_000));
        db_tx
            .set_address_balance_at_height(
                &address,
                random_amount,
                CoinOrTokenId::TokenId(random_token_id),
                block_height.next_height(),
            )
            .await
            .unwrap();

        let balances = db_tx.get_address_balances(address.as_str()).await.unwrap();
        assert_eq!(balances.len(), 1);
        let balance = balances.into_iter().next().unwrap();
        assert_eq!(balance.0, CoinOrTokenId::TokenId(random_token_id));
        assert_eq!(balance.1.amount, random_amount);
        assert_eq!(balance.1.decimals, random_num_decimals);

        let (_, pk2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let random_destination2 = Destination::PublicKeyHash(PublicKeyHash::from(&pk2));
        let token_change_authority = locked_token_data
            .clone()
            .change_authority(random_destination2.clone(), locked_token_data.next_nonce);

        db_tx
            .set_fungible_token_data(
                random_token_id,
                block_height.next_height().next_height(),
                token_change_authority.clone(),
            )
            .await
            .unwrap();
        let returned_token =
            db_tx.get_fungible_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_token, token_change_authority);

        let tokens = db_tx
            .get_fungible_tokens_by_authority(random_destination.clone())
            .await
            .unwrap();
        assert!(tokens.is_empty());

        let tokens = db_tx
            .get_fungible_tokens_by_authority(random_destination2.clone())
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], random_token_id);

        // after reorg go back to the previous token data
        db_tx.del_token_issuance_above_height(block_height).await.unwrap();
        let returned_token =
            db_tx.get_fungible_token_issuance(random_token_id).await.unwrap().unwrap();

        assert_eq!(returned_token, token_data);

        let tokens = db_tx.get_fungible_tokens_by_authority(random_destination).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], random_token_id);

        db_tx
            .del_token_issuance_above_height(block_height.prev_height().unwrap())
            .await
            .unwrap();

        let token = db_tx.get_fungible_token_issuance(random_token_id).await.unwrap();
        assert!(token.is_none());

        db_tx.commit().await.unwrap();
    }

    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let random_destination = Destination::PublicKeyHash(PublicKeyHash::from(&pk));

        let token_ticker = "XXXX".as_bytes().to_vec();
        let token_data = FungibleTokenData {
            token_ticker: token_ticker.clone(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "http://uri".as_bytes().to_vec(),
            circulating_supply: Amount::ZERO,
            total_supply: TokenTotalSupply::Unlimited,
            is_locked: false,
            frozen: IsTokenFrozen::No(IsTokenFreezable::Yes),
            authority: random_destination,
            next_nonce: AccountNonce::new(0),
        };

        let block_height = BlockHeight::new(rng.gen_range(1..100));
        let random_token_id1 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_fungible_token_issuance(random_token_id1, block_height, token_data.clone())
            .await
            .unwrap();

        let random_token_id2 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_fungible_token_issuance(random_token_id2, block_height, token_data.clone())
            .await
            .unwrap();

        let random_token_id3 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_fungible_token_issuance(random_token_id3, block_height, token_data.clone())
            .await
            .unwrap();

        let nft = NftIssuance::V0(NftIssuanceV0 {
            metadata: common::chain::tokens::Metadata {
                creator: None,
                name: "Name".as_bytes().to_vec(),
                description: "SomeNFT".as_bytes().to_vec(),
                ticker: token_ticker.clone(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: "123456".as_bytes().to_vec(),
            },
        });

        let (_, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let random_owner = Destination::PublicKeyHash(PublicKeyHash::from(&pk));
        let random_token_id4 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_nft_token_issuance(random_token_id4, block_height, nft.clone(), &random_owner)
            .await
            .unwrap();
        let random_token_id5 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_nft_token_issuance(random_token_id5, block_height, nft.clone(), &random_owner)
            .await
            .unwrap();
        let random_token_id6 = TokenId::new(H256::random_using(&mut rng));
        db_tx
            .set_nft_token_issuance(random_token_id6, block_height, nft.clone(), &random_owner)
            .await
            .unwrap();

        // will return all token and nft ids
        let ids = db_tx.get_token_ids(6, 0).await.unwrap();
        assert!(ids.contains(&random_token_id1));
        assert!(ids.contains(&random_token_id2));
        assert!(ids.contains(&random_token_id3));

        assert!(ids.contains(&random_token_id4));
        assert!(ids.contains(&random_token_id5));
        assert!(ids.contains(&random_token_id6));

        // will return all token and nft ids
        let ids = db_tx.get_token_ids_by_ticker(6, 0, &token_ticker).await.unwrap();
        assert!(ids.contains(&random_token_id1));
        assert!(ids.contains(&random_token_id2));
        assert!(ids.contains(&random_token_id3));

        assert!(ids.contains(&random_token_id4));
        assert!(ids.contains(&random_token_id5));
        assert!(ids.contains(&random_token_id6));

        // will return the tokens first
        let ids = db_tx.get_token_ids(3, 0).await.unwrap();
        assert!(ids.contains(&random_token_id1));
        assert!(ids.contains(&random_token_id2));
        assert!(ids.contains(&random_token_id3));

        // will return the tokens first
        let ids = db_tx.get_token_ids_by_ticker(3, 0, &token_ticker).await.unwrap();
        assert!(ids.contains(&random_token_id1));
        assert!(ids.contains(&random_token_id2));
        assert!(ids.contains(&random_token_id3));

        // will return the nft second
        let ids = db_tx.get_token_ids(3, 3).await.unwrap();
        assert!(ids.contains(&random_token_id4));
        assert!(ids.contains(&random_token_id5));
        assert!(ids.contains(&random_token_id6));

        // will return the nft second
        let ids = db_tx.get_token_ids_by_ticker(3, 3, &token_ticker).await.unwrap();
        assert!(ids.contains(&random_token_id4));
        assert!(ids.contains(&random_token_id5));
        assert!(ids.contains(&random_token_id6));

        let ids = db_tx.get_token_ids_by_ticker(0, 6, "NOT_FOUND".as_bytes()).await.unwrap();
        assert!(ids.is_empty());
    }

    // test coin and token statistics
    {
        let db_tx = storage.transaction_ro().await.unwrap();

        let random_token_id = TokenId::new(H256::random_using(&mut rng));
        let random_coin_or_token_id = CoinOrTokenId::TokenId(random_token_id);
        let random_statistic = match rng.gen_range(0..4) {
            0 => CoinOrTokenStatistic::CirculatingSupply,
            1 => CoinOrTokenStatistic::Staked,
            2 => CoinOrTokenStatistic::Burned,
            _ => CoinOrTokenStatistic::Preminted,
        };

        let amount = db_tx.get_statistic(random_statistic, random_coin_or_token_id).await.unwrap();
        assert!(amount.is_none());

        drop(db_tx);

        let mut db_tx = storage.transaction_rw().await.unwrap();

        let random_block_height = BlockHeight::new(rng.gen_range(1..100));
        let random_amount = Amount::from_atoms(rng.gen_range(0..100_000));
        db_tx
            .set_statistic(
                random_statistic,
                random_coin_or_token_id,
                random_block_height,
                random_amount,
            )
            .await
            .unwrap();

        let returned_amount =
            db_tx.get_statistic(random_statistic, random_coin_or_token_id).await.unwrap();

        assert_eq!(returned_amount, Some(random_amount));

        let random_amount2 = Amount::from_atoms(rng.gen_range(0..100_000));

        db_tx
            .set_statistic(
                random_statistic,
                random_coin_or_token_id,
                random_block_height.next_height(),
                random_amount2,
            )
            .await
            .unwrap();

        let returned_amount =
            db_tx.get_statistic(random_statistic, random_coin_or_token_id).await.unwrap();

        assert_eq!(returned_amount, Some(random_amount2));

        // after reorg go back to the previous token data
        db_tx.del_statistics_above_height(random_block_height).await.unwrap();
        let returned_amount =
            db_tx.get_statistic(random_statistic, random_coin_or_token_id).await.unwrap();

        assert_eq!(returned_amount, Some(random_amount));

        db_tx
            .del_statistics_above_height(random_block_height.prev_height().unwrap())
            .await
            .unwrap();

        let returned_amount =
            db_tx.get_statistic(random_statistic, random_coin_or_token_id).await.unwrap();
        assert!(returned_amount.is_none());

        db_tx.commit().await.unwrap();
    }

    // test orders
    orders(&mut rng, &mut storage).await;

    Ok(())
}

async fn orders<'a, S: for<'b> Transactional<'b>>(
    rng: &mut (impl Rng + CryptoRng),
    storage: &'a mut S,
) {
    let chain_config = common::chain::config::create_regtest();
    {
        let db_tx = storage.transaction_ro().await.unwrap();
        let random_order_id = OrderId::new(H256::random_using(rng));
        let order = db_tx.get_order(random_order_id).await.unwrap();
        assert!(order.is_none());

        let orders = db_tx.get_all_orders(10, 0).await.unwrap();
        assert!(orders.is_empty());
    }

    let token1 = TokenId::new(H256::random_using(rng));
    let token2 = TokenId::new(H256::random_using(rng));

    let (order1_id, order1) = random_order(
        rng,
        BlockHeight::new(1),
        CoinOrTokenId::Coin,
        CoinOrTokenId::TokenId(token1),
    );
    let (order2_id, order2) = random_order(
        rng,
        BlockHeight::new(2),
        CoinOrTokenId::TokenId(token1),
        CoinOrTokenId::TokenId(token2),
    );
    let (order3_id, order3) = random_order(
        rng,
        BlockHeight::new(3),
        CoinOrTokenId::Coin,
        CoinOrTokenId::TokenId(token2),
    );
    let (order4_id, order4) = random_order(
        rng,
        BlockHeight::new(4),
        CoinOrTokenId::TokenId(token2),
        CoinOrTokenId::TokenId(token1),
    );
    let (order5_id, order5) = random_order(
        rng,
        BlockHeight::new(5),
        CoinOrTokenId::TokenId(token1),
        CoinOrTokenId::Coin,
    );
    let (order6_id, order6) = random_order(
        rng,
        BlockHeight::new(6),
        CoinOrTokenId::TokenId(token1),
        CoinOrTokenId::TokenId(token2),
    );

    let mut db_tx = storage.transaction_rw().await.unwrap();

    let block_height = BlockHeight::new(rng.gen_range(100..1000));

    db_tx
        .set_order_at_height(order1_id, &order1, BlockHeight::new(1))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order1_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order1);

    db_tx
        .set_order_at_height(order2_id, &order2, BlockHeight::new(2))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order2_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order2);

    db_tx
        .set_order_at_height(order3_id, &order3, BlockHeight::new(3))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order3_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order3);

    db_tx
        .set_order_at_height(order4_id, &order4, BlockHeight::new(4))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order4_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order4);

    db_tx
        .set_order_at_height(order5_id, &order5, BlockHeight::new(5))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order5_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order5);

    db_tx
        .set_order_at_height(order6_id, &order6, BlockHeight::new(6))
        .await
        .unwrap();
    let returned_order = db_tx.get_order(order6_id).await.unwrap().unwrap();
    assert_eq!(returned_order, order6);

    // Get all
    let all_orders = db_tx.get_all_orders(10, 0).await.unwrap();
    assert_eq!(all_orders.len(), 6);
    assert_eq!(
        all_orders,
        vec![
            (order6_id, order6.clone()),
            (order5_id, order5.clone()),
            (order4_id, order4.clone()),
            (order3_id, order3.clone()),
            (order2_id, order2.clone()),
            (order1_id, order1.clone()),
        ]
    );

    // Fill one order
    let order2_filled = order2.clone().fill(&chain_config, block_height, Amount::from_atoms(1));
    db_tx
        .set_order_at_height(order2_id, &order2_filled, block_height.next_height())
        .await
        .unwrap();

    // Get per page
    let all_orders_page_1 = db_tx.get_all_orders(3, 0).await.unwrap();
    assert_eq!(
        all_orders_page_1,
        vec![
            (order6_id, order6.clone()),
            (order5_id, order5.clone()),
            (order4_id, order4.clone())
        ]
    );

    let all_orders_page_2 = db_tx.get_all_orders(3, 3).await.unwrap();
    assert_eq!(
        all_orders_page_2,
        vec![
            (order3_id, order3.clone()),
            (order2_id, order2_filled.clone()),
            (order1_id, order1.clone())
        ]
    );

    // Check trading pairs
    let ml_tkn1 = db_tx
        .get_orders_for_trading_pair((CoinOrTokenId::Coin, CoinOrTokenId::TokenId(token1)), 10, 0)
        .await
        .unwrap();
    assert_eq!(
        ml_tkn1,
        vec![(order5_id, order5.clone()), (order1_id, order1.clone())]
    );

    let tkn2_tkn1 = db_tx
        .get_orders_for_trading_pair(
            (
                CoinOrTokenId::TokenId(token2),
                CoinOrTokenId::TokenId(token1),
            ),
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        tkn2_tkn1,
        vec![
            (order6_id, order6.clone()),
            (order4_id, order4.clone()),
            (order2_id, order2_filled)
        ]
    );

    // Delete filled order
    db_tx.del_orders_above_height(block_height).await.unwrap();
    let all_orders = db_tx.get_all_orders(10, 0).await.unwrap();
    assert_eq!(all_orders.len(), 6);
    assert_eq!(
        all_orders,
        vec![
            (order6_id, order6.clone()),
            (order5_id, order5.clone()),
            (order4_id, order4.clone()),
            (order3_id, order3.clone()),
            (order2_id, order2.clone()),
            (order1_id, order1.clone()),
        ]
    );

    // Freeze an order
    let order1_frozen = order1.clone().freeze();
    db_tx
        .set_order_at_height(order1_id, &order1_frozen, block_height.next_height())
        .await
        .unwrap();

    let all_orders = db_tx.get_all_orders(10, 0).await.unwrap();
    assert_eq!(all_orders.len(), 6);
    assert_eq!(
        all_orders,
        vec![
            (order6_id, order6),
            (order5_id, order5),
            (order4_id, order4),
            (order3_id, order3),
            (order2_id, order2),
            (order1_id, order1_frozen),
        ]
    );
}

fn random_order(
    rng: &mut (impl Rng + CryptoRng),
    creation_height: BlockHeight,
    ask_currency: CoinOrTokenId,
    give_currency: CoinOrTokenId,
) -> (OrderId, Order) {
    let order_id = OrderId::new(H256::random_using(rng));
    let (_, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let conclude_destination = Destination::PublicKeyHash(PublicKeyHash::from(&pk));
    let give_amount = Amount::from_atoms(rng.gen_range(1000..10000));
    let ask_amount = Amount::from_atoms(rng.gen_range(1000..10000));
    let order = Order {
        creation_block_height: creation_height,
        conclude_destination,
        give_currency,
        initially_given: give_amount,
        give_balance: give_amount,
        ask_currency,
        initially_asked: ask_amount,
        ask_balance: ask_amount,
        is_frozen: false,
        next_nonce: AccountNonce::new(rng.gen::<u64>()),
    };
    (order_id, order)
}

pub fn build_tests<S, Fut, F: Fn() -> Fut + Send + Sync + 'static>(
    storage_maker: Arc<F>,
) -> impl Iterator<Item = libtest_mimic::Trial>
where
    Fut: Future<Output = S> + Send + 'static,
    S: ApiServerStorage + Send + 'static,
{
    vec![
        make_test!(initialization, storage_maker.clone()),
        make_test!(set_get, storage_maker),
    ]
    .into_iter()
}
