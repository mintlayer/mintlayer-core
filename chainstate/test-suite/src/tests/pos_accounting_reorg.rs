// Copyright (c) 2022 RBB S.r.l
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

use itertools::Itertools;
use std::num::NonZeroU64;

use super::helpers::{
    new_pub_key_destination, pos::create_stake_pool_data_with_all_reward_to_owner,
};

use accounting::{DataDelta, DeltaAmountCollection, DeltaDataCollection};
use chainstate::BlockSource;
use chainstate_storage::{inmemory::Store, BlockchainStorageWrite, TransactionRw, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        config::{create_unit_test_config, Builder as ConfigBuilder},
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::OutputValue,
        Destination, GenBlock, OutPointSourceId, PoolId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::PoSAccountingDeltaData;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

// Produce `genesis -> a` chain, then a parallel `genesis -> b -> c` that should trigger a reorg.
// Block `a` and block `c` have stake pool operation.
// Check that after reorg all accounting data from block `a` was removed and from block `c` added to storage.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let epoch_length_params = [
            NonZeroU64::new(1).unwrap(), // reorg between epochs, every block is epoch boundary
            NonZeroU64::new(2).unwrap(), // reorg between epochs, `c` starts new epoch
            NonZeroU64::new(3).unwrap(), // reorg within epoch
        ];
        let sealed_epoch_distance_from_tip_params: [usize; 3] = [
            0, // tip == sealed
            1, // sealed is behind the tip by 1 epoch
            2, // sealed is behind the tip by 2 epochs
        ];

        for (epoch_length, sealed_epoch_distance_from_tip) in epoch_length_params
            .into_iter()
            .cartesian_product(sealed_epoch_distance_from_tip_params)
        {
            let storage = Store::new_empty().unwrap();
            let mut rng = make_seedable_rng(seed);
            let chain_config = ConfigBuilder::test_chain()
                .epoch_length(epoch_length)
                .sealed_epoch_distance_from_tip(sealed_epoch_distance_from_tip)
                .build();
            let mut tf = TestFramework::builder(&mut rng)
                .with_storage(storage.clone())
                .with_chain_config(chain_config.clone())
                .build();
            let genesis_id = tf.genesis().get_id();
            let min_stake_pool_pledge =
                tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
            let pledge_amount = Amount::from_atoms(
                rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)),
            );

            // prepare tx_a
            let destination_a = new_pub_key_destination(&mut rng);
            let (_, vrf_pub_key_a) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let genesis_outpoint = UtxoOutPoint::new(
                OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                0,
            );
            let pool_id_a = pos_accounting::make_pool_id(&genesis_outpoint);
            let tx_a = TransactionBuilder::new()
                .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
                .add_output(TxOutput::CreateStakePool(
                    pool_id_a,
                    Box::new(StakePoolData::new(
                        pledge_amount,
                        anyonecanspend_address(),
                        vrf_pub_key_a,
                        destination_a,
                        PerThousand::new(0).unwrap(),
                        Amount::ZERO,
                    )),
                ))
                .build();

            // prepare tx_b
            let tx_b = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                    empty_witness(&mut rng),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(pledge_amount),
                    anyonecanspend_address(),
                ))
                .build();

            // prepare tx_c
            let destination_c = new_pub_key_destination(&mut rng);
            let (_, vrf_pub_key_c) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
            let tx_b_outpoint0 = UtxoOutPoint::new(tx_b.transaction().get_id().into(), 0);
            let pool_id_c = pos_accounting::make_pool_id(&tx_b_outpoint0);
            let tx_c = TransactionBuilder::new()
                .add_input(tx_b_outpoint0.into(), empty_witness(&mut rng))
                .add_output(TxOutput::CreateStakePool(
                    pool_id_c,
                    Box::new(StakePoolData::new(
                        pledge_amount,
                        anyonecanspend_address(),
                        vrf_pub_key_c,
                        destination_c,
                        PerThousand::new(0).unwrap(),
                        Amount::ZERO,
                    )),
                ))
                .build();

            // create block a
            let block_a = tf.make_block_builder().add_transaction(tx_a).build();
            let block_a_index =
                tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
            assert_eq!(
                tf.best_block_id(),
                Id::<GenBlock>::from(*block_a_index.block_id())
            );

            // create block b
            let block_b = tf
                .make_block_builder()
                .with_parent(genesis_id.into())
                .add_transaction(tx_b.clone())
                .build();
            let block_b_id = block_b.get_id();
            tf.process_block(block_b, BlockSource::Local).unwrap();

            // no reorg here
            assert_eq!(
                tf.best_block_id(),
                Id::<GenBlock>::from(*block_a_index.block_id())
            );

            // create block c
            let block_c = tf
                .make_block_builder()
                .with_parent(block_b_id.into())
                .add_transaction(tx_c.clone())
                .build_and_process()
                .unwrap()
                .unwrap();

            assert_eq!(
                tf.best_block_id(),
                Id::<GenBlock>::from(*block_c.block_id())
            );

            // Accounting data in storage after reorg should equal to the data in storage for chain
            // where reorg never happened.
            //
            // Construct fresh `genesis -> b -> c` chain as a reference
            let expected_storage = {
                let storage = Store::new_empty().unwrap();
                let block_a_epoch =
                    chain_config.epoch_index_from_height(&block_a_index.block_height());
                let mut tf = TestFramework::builder(&mut rng)
                    .with_storage(storage.clone())
                    .with_chainstate_config(tf.chainstate().get_chainstate_config())
                    .with_chain_config(chain_config)
                    .build();

                {
                    // manually add block_a info
                    let mut db_tx = storage.transaction_rw(None).unwrap();
                    db_tx.set_block_index(&block_a_index).unwrap();
                    db_tx.add_block(&block_a).unwrap();

                    // reorg leaves a trace in delta index, because deltas are never removed on undo;
                    // so we need to manually add None-None delta left from block_a
                    let block_a_delta = PoSAccountingDeltaData {
                        pool_data: DeltaDataCollection::from_iter(
                            [(pool_id_a, DataDelta::new(None, None))].into_iter(),
                        ),
                        pool_balances: DeltaAmountCollection::new(),
                        pool_delegation_shares: DeltaAmountCollection::new(),
                        delegation_balances: DeltaAmountCollection::new(),
                        delegation_data: DeltaDataCollection::new(),
                    };
                    db_tx.set_accounting_epoch_delta(block_a_epoch, &block_a_delta).unwrap();

                    db_tx.commit().unwrap();
                }

                let block_b = tf
                    .make_block_builder()
                    .with_parent(genesis_id.into())
                    .add_transaction(tx_b)
                    .build_and_process()
                    .unwrap()
                    .unwrap();

                tf.make_block_builder()
                    .with_parent((*block_b.block_id()).into())
                    .add_transaction(tx_c)
                    .build_and_process()
                    .unwrap();

                storage
            };

            assert_eq!(storage.dump_raw(), expected_storage.dump_raw());
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn long_chain_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (staking_sk, staking_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let pool_id = PoolId::new(H256::random_using(&mut rng));
        let stake_pool_pledge = create_unit_test_config().min_stake_pool_pledge();
        let stake_pool_data = StakePoolData::new(
            stake_pool_pledge,
            Destination::PublicKey(staking_pk),
            vrf_pk,
            Destination::AnyoneCanSpend,
            PerThousand::new(1000).unwrap(),
            Amount::ZERO,
        );

        let mint_amount = Amount::from_atoms(rng.gen_range(100..100_000));
        let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
            mint_amount,
            pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time =
            chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.get());

        let common_block_id = tf
            .create_chain_pos(
                &tf.genesis().get_id().into(),
                5,
                &mut rng,
                &staking_sk,
                &vrf_sk,
            )
            .unwrap();

        let old_tip = tf
            .create_chain_pos(&common_block_id, 100, &mut rng, &staking_sk, &vrf_sk)
            .unwrap();

        let new_tip = tf
            .create_chain_pos(&common_block_id, 101, &mut rng, &staking_sk, &vrf_sk)
            .unwrap();

        assert_ne!(old_tip, new_tip);
        assert_eq!(new_tip, tf.best_block_id());
    });
}

// Produce `genesis -> a -> b` chain, where block `a` creates additional staking pool and
// block `b` decommissions the pool from genesis.
// Then produce a parallel `genesis -> a -> c` that should trigger a in-memory reorg for block `b`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn in_memory_reorg_disconnect_produce_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        amount_to_stake,
        pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time =
        chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.get());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, staking_sk_2) =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk);
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = pos_accounting::make_pool_id(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder(&mut rng)
        .add_transaction(stake_pool_2_tx)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap();
    let block_a_id = tf.best_block_id();

    // produce block `b` at height 2: decommission pool_1 with ProduceBlock from genesis
    let produce_block_outpoint = UtxoOutPoint::new(block_a_id.into(), 0);

    let decommission_pool_tx = TransactionBuilder::new()
        .add_input(produce_block_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_stake),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    let block_b_index = tf
        .make_pos_block_builder(&mut rng)
        .add_transaction(decommission_pool_tx)
        .with_stake_pool(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_block_signing_key(staking_sk_2.clone())
        .with_stake_spending_key(staking_sk_2.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for block `b`
    tf.make_pos_block_builder(&mut rng)
        .with_parent(block_a_id)
        .with_stake_pool(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_block_signing_key(staking_sk_2.clone())
        .with_stake_spending_key(staking_sk_2)
        .with_vrf_key(vrf_sk)
        .build_and_process()
        .unwrap();
    // block_b is still the tip
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );
}

// Produce `genesis -> a -> b` chain, where block `a` creates additional staking pool and
// block `b` decommissions the pool from `a`.
// Then produce a parallel `genesis -> a -> c` that should trigger a in-memory reorg for block `b`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn in_memory_reorg_disconnect_create_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        amount_to_stake,
        pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time =
        chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.get());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, _) =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk);
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = pos_accounting::make_pool_id(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder(&mut rng)
        .add_transaction(stake_pool_2_tx)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap();
    let block_a_id = tf.best_block_id();

    // produce block `b` at height 2: decommission pool_2 from prev block
    let stake_pool_2_outpoint = UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0);

    let decommission_pool_tx = TransactionBuilder::new()
        .add_input(stake_pool_2_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_stake),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    let block_b_index = tf
        .make_pos_block_builder(&mut rng)
        .add_transaction(decommission_pool_tx)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process()
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for block `b`
    tf.make_pos_block_builder(&mut rng)
        .with_parent(block_a_id)
        .with_block_signing_key(staking_sk.clone())
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process()
        .unwrap();
    // block_b is still the tip
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );
}
