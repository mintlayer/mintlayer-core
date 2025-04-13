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

use std::num::NonZeroU64;

use super::helpers::new_pub_key_destination;

use accounting::{DataDelta, DeltaAmountCollection, DeltaDataCollection};
use chainstate::BlockSource;
use chainstate_storage::{BlockchainStorageWrite, TransactionRw, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, create_stake_pool_data_with_all_reward_to_staker, empty_witness,
    TestFramework, TestStore, TransactionBuilder,
};
use common::{
    chain::{
        config::{create_unit_test_config, Builder as ConfigBuilder},
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        AccountNonce, AccountOutPoint, AccountSpending, DelegationId, Destination, GenBlock,
        OutPointSourceId, PoolId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Id, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::PoSAccountingDeltaData;
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

// Produce `genesis -> a` chain, then a parallel `genesis -> b -> c` that should trigger a reorg.
// Block `a` and block `c` have stake pool operation.
// Check that after reorg all accounting data from block `a` was removed and from block `c` added to storage.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), NonZeroU64::new(1).unwrap(), 0)]
#[case(Seed::from_entropy(), NonZeroU64::new(1).unwrap(), 1)]
#[case(Seed::from_entropy(), NonZeroU64::new(1).unwrap(), 2)]
#[case(Seed::from_entropy(), NonZeroU64::new(2).unwrap(), 0)]
#[case(Seed::from_entropy(), NonZeroU64::new(2).unwrap(), 1)]
#[case(Seed::from_entropy(), NonZeroU64::new(2).unwrap(), 2)]
#[case(Seed::from_entropy(), NonZeroU64::new(3).unwrap(), 0)]
#[case(Seed::from_entropy(), NonZeroU64::new(3).unwrap(), 1)]
#[case(Seed::from_entropy(), NonZeroU64::new(3).unwrap(), 2)]
fn stake_pool_reorg(
    #[case] seed: Seed,
    #[case] epoch_length: NonZeroU64,
    #[case] sealed_epoch_distance_from_tip: usize,
) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
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
        let pledge_amount =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));

        // prepare tx_a
        let destination_a = new_pub_key_destination(&mut rng);
        let (_, vrf_pub_key_a) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id_a = PoolId::from_utxo(&genesis_outpoint);
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
        let pool_id_c = PoolId::from_utxo(&tx_b_outpoint0);
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
        let block_a = tf.make_block_builder().add_transaction(tx_a).build(&mut rng);
        let block_a_index = tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block b
        let block_b = tf
            .make_block_builder()
            .with_parent(genesis_id.into())
            .add_transaction(tx_b.clone())
            .build(&mut rng);
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
            .build_and_process(&mut rng)
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
            let storage = TestStore::new_empty().unwrap();
            let block_a_epoch = chain_config.epoch_index_from_height(&block_a_index.block_height());
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

                // reorg leaves a trace in delta index
                // because deltas are only removed on undo if the entire epoch is disconnected;
                // so we need to manually add None-None delta left from block_a
                if !tf
                    .chain_config()
                    .is_last_block_in_epoch(&block_a_index.block_height().prev_height().unwrap())
                {
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
                }

                db_tx.commit().unwrap();
            }

            let block_b = tf
                .make_block_builder()
                .with_parent(genesis_id.into())
                .add_transaction(tx_b)
                .build_and_process(&mut rng)
                .unwrap()
                .unwrap();

            tf.make_block_builder()
                .with_parent((*block_b.block_id()).into())
                .add_transaction(tx_c)
                .build_and_process(&mut rng)
                .unwrap();

            storage
        };

        assert_eq!(
            storage.transaction_ro().unwrap().dump_raw(),
            expected_storage.transaction_ro().unwrap().dump_raw()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_same_stake_pool_after_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
        let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

        let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            amount_to_stake,
            vrf_pk.clone(),
        );

        let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
            &mut rng,
            (amount_to_stake * 2).unwrap(),
            genesis_pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time = chain_config.target_block_spacing();
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        // prepare tx with pool creation
        let destination_a = new_pub_key_destination(&mut rng);
        let (_, vrf_pub_key_a) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let genesis_block_id = tf.genesis().get_id().into();
        let genesis_outpoint =
            UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_block_id), 0);
        let pool_id = PoolId::from_utxo(&genesis_outpoint);
        let create_pool_tx_builder = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(StakePoolData::new(
                    amount_to_stake,
                    anyonecanspend_address(),
                    vrf_pub_key_a,
                    destination_a,
                    PerThousand::new(0).unwrap(),
                    Amount::ZERO,
                )),
            ));

        // create block a
        let block_a = tf
            .make_pos_block_builder()
            .add_transaction(create_pool_tx_builder.clone().build())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let block_a_index = tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block b

        // add another output so that block id would be different
        let create_pool_tx_2 = create_pool_tx_builder
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let block_b = tf
            .make_pos_block_builder()
            .with_parent(genesis_block_id)
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .add_transaction(create_pool_tx_2.clone())
            .build(&mut rng);
        let block_b_id = block_b.get_id();
        tf.process_block(block_b, BlockSource::Local).unwrap();

        // no reorg here
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block c
        let block_c = tf
            .make_pos_block_builder()
            .with_parent(block_b_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk)
            .with_vrf_key(vrf_sk.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_c.block_id())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_same_delegation_after_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
        let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

        let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            amount_to_stake,
            vrf_pk.clone(),
        );

        let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
            &mut rng,
            (amount_to_stake * 2).unwrap(),
            genesis_pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time = chain_config.target_block_spacing();
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        // prepare txs with delegation creation
        let genesis_block_id = tf.genesis().get_id().into();
        let genesis_outpoint =
            UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_block_id), 0);
        let delegation_id = DelegationId::from_utxo(&genesis_outpoint);
        let create_delegation_tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                genesis_pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(2000)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(create_delegation_tx.transaction().get_id().into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(
                Amount::from_atoms(1000),
                delegation_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build();

        // create block a
        let block_a = tf
            .make_pos_block_builder()
            .with_transactions(vec![
                create_delegation_tx.clone(),
                delegate_staking_tx.clone(),
            ])
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let block_a_index = tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block b

        // add another tx so that block id would be different
        let additional_transfer_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(delegate_staking_tx.transaction().get_id().into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let block_b = tf
            .make_pos_block_builder()
            .with_parent(genesis_block_id)
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .with_transactions(vec![
                create_delegation_tx,
                delegate_staking_tx,
                additional_transfer_tx,
            ])
            .build(&mut rng);
        let block_b_id = block_b.get_id();
        tf.process_block(block_b, BlockSource::Local).unwrap();

        // no reorg here
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block c
        let block_c = tf
            .make_pos_block_builder()
            .with_parent(block_b_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk)
            .with_vrf_key(vrf_sk.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_c.block_id())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_for_staking_pool_in_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
        let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

        let (staking_sk, staking_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let stake_pool_data = StakePoolData::new(
            amount_to_stake,
            Destination::PublicKey(staking_pk),
            vrf_pk.clone(),
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::from_atoms(1),
        );

        let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
            &mut rng,
            (amount_to_stake * 2).unwrap(),
            genesis_pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time = chain_config.target_block_spacing();
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        // create block a with delegation 1
        let genesis_block_id = tf.genesis().get_id().into();
        let genesis_outpoint =
            UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_block_id), 0);
        let delegation_id_1 = DelegationId::from_utxo(&genesis_outpoint);
        let create_delegation_tx_1 = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                genesis_pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(2000)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(create_delegation_tx_1.transaction().get_id().into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(
                Amount::from_atoms(1000),
                delegation_id_1,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx_1.transaction().get_id();

        let block_a = tf
            .make_pos_block_builder()
            .with_transactions(vec![create_delegation_tx_1, delegate_staking_tx_1])
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let block_a_index = tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block b with delegation 2
        let delegation_id_2 =
            DelegationId::from_utxo(&UtxoOutPoint::new(delegate_staking_tx_id.into(), 1));
        let create_delegation_tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(delegate_staking_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                genesis_pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let create_delegation_tx_2_id = create_delegation_tx_2.transaction().get_id();
        let delegate_staking_tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(create_delegation_tx_2_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(
                Amount::from_atoms(1000),
                delegation_id_2,
            ))
            .build();

        let block_b = tf
            .make_pos_block_builder()
            .with_transactions(vec![create_delegation_tx_2, delegate_staking_tx_2])
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let block_b_index = tf.process_block(block_b.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_b_index.block_id())
        );

        // create empty block c from a
        let block_c = tf
            .make_pos_block_builder()
            .with_parent((*block_a_index.block_id()).into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let block_c_id = block_c.get_id();
        tf.process_block(block_c, BlockSource::Local).unwrap();

        // no reorg here
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_b_index.block_id())
        );

        // create empty block d
        let block_d = tf
            .make_pos_block_builder()
            .with_parent(block_c_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk)
            .with_vrf_key(vrf_sk.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_d.block_id())
        );
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

        let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
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
            &mut rng,
            mint_amount,
            genesis_pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time = chain_config.target_block_spacing();
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        let common_block_id = tf
            .create_chain_pos(
                &mut rng,
                &tf.genesis().get_id().into(),
                5,
                genesis_pool_id,
                &staking_sk,
                &vrf_sk,
            )
            .unwrap();

        let old_tip = tf
            .create_chain_pos(
                &mut rng,
                &common_block_id,
                100,
                genesis_pool_id,
                &staking_sk,
                &vrf_sk,
            )
            .unwrap();

        let new_tip = tf
            .create_chain_pos(
                &mut rng,
                &common_block_id,
                101,
                genesis_pool_id,
                &staking_sk,
                &vrf_sk,
            )
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

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        amount_to_stake,
        genesis_pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, staking_sk_2) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = PoolId::from_utxo(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder()
        .add_transaction(stake_pool_2_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
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
        .make_pos_block_builder()
        .add_transaction(decommission_pool_tx)
        .with_stake_pool_id(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_stake_spending_key(staking_sk_2.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for block `b`
    tf.make_pos_block_builder()
        .with_parent(block_a_id)
        .with_stake_pool_id(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_stake_spending_key(staking_sk_2)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
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

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        amount_to_stake,
        genesis_pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = PoolId::from_utxo(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder()
        .add_transaction(stake_pool_2_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
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
        .make_pos_block_builder()
        .add_transaction(decommission_pool_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for block `b`
    tf.make_pos_block_builder()
        .with_parent(block_a_id)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap();
    // block_b is still the tip
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );
}

// Use 2 chainstates to produce 2 branches from a common genesis using PoS.
// Chainstate1: genesis <- a
// Chainstate2: genesis <- b <- c
// Process blocks from Chainstate2 using Chainstate1 and check that reorg happens.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_reorg_simple(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staker_sk, staker_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let (chain_config_builder, genesis_pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staker_pk, vrf_pk,
        );
    let chain_config = chain_config_builder.build();

    let target_block_time = chain_config.target_block_spacing();

    let mut tf1 = TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
    let mut tf2 = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    tf1.progress_time_seconds_since_epoch(target_block_time.as_secs());
    tf2.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // Block A
    tf1.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    // Block B
    let block_b = tf2
        .make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build(&mut rng);
    tf2.process_block(block_b.clone(), BlockSource::Local).unwrap();

    // Block C
    let block_c = tf2
        .make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk)
        .with_vrf_key(vrf_sk)
        .build(&mut rng);
    let block_c_id = block_c.get_id();
    tf2.process_block(block_c.clone(), BlockSource::Local).unwrap();

    assert_eq!(<Id<GenBlock>>::from(block_c_id), tf2.best_block_id());

    // Try to switch to a new branch

    tf1.chainstate
        .preliminary_headers_check(std::slice::from_ref(block_b.header()))
        .unwrap();
    let block_b = tf1.chainstate.preliminary_block_check(block_b).unwrap();
    tf1.process_block(block_b, BlockSource::Peer).unwrap();

    tf1.chainstate
        .preliminary_headers_check(std::slice::from_ref(block_c.header()))
        .unwrap();
    let block_c = tf1.chainstate.preliminary_block_check(block_c).unwrap();
    tf1.process_block(block_c, BlockSource::Peer).unwrap().unwrap();

    assert_eq!(<Id<GenBlock>>::from(block_c_id), tf1.best_block_id());
}

// Produce `genesis -> a -> b -> c` chain, where block `a` creates delegation with some coins and
// block `b` and `c` spend it.
// Then produce a parallel `genesis -> a -> d` that should trigger a in-memory reorg for blocks `b` and `c`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn in_memory_reorg_disconnect_spend_delegation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        amount_to_stake,
        genesis_pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // produce block `a` at height 1 and create delegation and delegate some coins
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let delegation_id = DelegationId::from_utxo(&genesis_outpoint);
    let create_delegation_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            genesis_pool_id,
        ))
        .build();
    let create_delegation_tx_id = create_delegation_tx.transaction().get_id();

    let delegate_staking_tx = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(create_delegation_tx_id.into(), 0).into(),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(500)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::DelegateStaking(
            Amount::from_atoms(500),
            delegation_id,
        ))
        .build();

    tf.make_pos_block_builder()
        .with_transactions(vec![create_delegation_tx, delegate_staking_tx])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();
    let block_a_id = tf.best_block_id();

    // produce block `b` at height 2 and spend some coins from delegation
    let spend_delegation_1_outpoint = AccountOutPoint::new(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(100)),
    );

    let spend_delegation_1_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Account(spend_delegation_1_outpoint),
            empty_witness(&mut rng),
        )
        .build();

    let block_b_index = tf
        .make_pos_block_builder()
        .add_transaction(spend_delegation_1_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_b_index.block_id()),
        tf.best_block_id()
    );

    // produce block `c` at height 3 and spend the rest from delegation
    let spend_delegation_2_outpoint = AccountOutPoint::new(
        AccountNonce::new(1),
        AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(400)),
    );

    let spend_delegation_2_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Account(spend_delegation_2_outpoint),
            empty_witness(&mut rng),
        )
        .build();

    let block_c_index = tf
        .make_pos_block_builder()
        .add_transaction(spend_delegation_2_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_c_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for block `c`
    tf.make_pos_block_builder()
        .with_parent(block_a_id)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap();
    // block_c is still the tip
    assert_eq!(
        Id::<GenBlock>::from(*block_c_index.block_id()),
        tf.best_block_id()
    );
}

// Produce `genesis -> a -> b -> c -> d` chain, where block `a` creates new pool,
// block `b` creates delegation with some coins, block `c` decommissions new pool and
// block `d` spend the entire delegation.
// Then produce a parallel `genesis -> a -> e` that should trigger a in-memory reorg for blocks `b`, `c` and `d`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn in_memory_reorg_disconnect_spend_delegation_from_decommissioned(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk.clone());

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        (amount_to_stake * 2).unwrap(),
        genesis_pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = PoolId::from_utxo(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder()
        .add_transaction(stake_pool_2_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();
    let block_a_id = tf.best_block_id();

    // produce block `b` at height 2: create delegation and delegation some coins
    let block_a_transfer_outpoint = UtxoOutPoint::new(stake_pool_2_tx_id.into(), 1);
    let delegation_id = DelegationId::from_utxo(&block_a_transfer_outpoint);
    let create_delegation_tx = TransactionBuilder::new()
        .add_input(block_a_transfer_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_2_id,
        ))
        .build();
    let create_delegation_tx_id = create_delegation_tx.transaction().get_id();

    let delegate_staking_tx = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(create_delegation_tx_id.into(), 0).into(),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::DelegateStaking(
            Amount::from_atoms(1000),
            delegation_id,
        ))
        .build();

    tf.make_pos_block_builder()
        .with_transactions(vec![create_delegation_tx, delegate_staking_tx])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    // produce block `c` at height 3: decommission pool_2
    let produce_block_outpoint = UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0);

    let decommission_pool_tx = TransactionBuilder::new()
        .add_input(produce_block_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_stake),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    let block_c_index = tf
        .make_pos_block_builder()
        .add_transaction(decommission_pool_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_c_index.block_id()),
        tf.best_block_id()
    );

    // produce block `d` at height 4 and spend whole delegation
    let spend_delegation_2_outpoint = AccountOutPoint::new(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(1000)),
    );

    let spend_delegation_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Account(spend_delegation_2_outpoint),
            empty_witness(&mut rng),
        )
        .build();

    let block_d_index = tf
        .make_pos_block_builder()
        .add_transaction(spend_delegation_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        Id::<GenBlock>::from(*block_d_index.block_id()),
        tf.best_block_id()
    );

    // produce block at height 2 that should trigger in memory reorg for blocks `b`, `c`, `d`
    tf.make_pos_block_builder()
        .with_parent(block_a_id)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap();
    // block_d is still the tip
    assert_eq!(
        Id::<GenBlock>::from(*block_d_index.block_id()),
        tf.best_block_id()
    );
}

// Create additional pool in block_a at height 1.
// Produce 2 branches from a common genesis using PoS. Each branch uses separate staking keys.
// Branch 1: genesis <- a <= b
// Build block `c` from block a but do not submit it
// Branch 2 : genesis <- a <- d <- e
// Then append block_c to block_b
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_submit_new_block_after_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staker_sk, staker_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let (vrf_sk_2, vrf_pk_2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let (chain_config_builder, genesis_pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staker_pk, vrf_pk,
        );
    let chain_config = chain_config_builder.build();
    let target_block_time = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();

    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // produce block `a` at height 1 and create additional pool
    let (stake_pool_data_2, staker_sk_2) = create_stake_pool_data_with_all_reward_to_staker(
        &mut rng,
        chain_config.min_stake_pool_pledge(),
        vrf_pk_2,
    );
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_2_id = PoolId::from_utxo(&genesis_outpoint);
    let stake_pool_2_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            pool_2_id,
            Box::new(stake_pool_data_2),
        ))
        .build();
    let stake_pool_2_tx_id = stake_pool_2_tx.transaction().get_id();
    tf.make_pos_block_builder()
        .add_transaction(stake_pool_2_tx)
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();
    let block_a_id = tf.best_block_id();

    // Produce block_b
    let block_b_index = tf
        .make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    let block_b_id: Id<GenBlock> = (*block_b_index.block_id()).into();
    assert_eq!(block_a_id, *block_b_index.prev_block_id());
    assert_eq!(block_b_id, tf.best_block_id());

    // Build block_c but do not process it
    let block_c = tf
        .make_pos_block_builder()
        .with_stake_pool_id(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_stake_spending_key(staker_sk_2.clone())
        .with_vrf_key(vrf_sk_2.clone())
        .build(&mut rng);
    let block_c_id = block_c.get_id();

    // Produce block_d from block_a as an alternative chain with second pool
    let block_d = tf
        .make_pos_block_builder()
        .with_parent(block_a_id)
        .with_stake_pool_id(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(stake_pool_2_tx_id.into(), 0))
        .with_stake_spending_key(staker_sk_2.clone())
        .with_vrf_key(vrf_sk_2.clone())
        .build(&mut rng);
    let block_d_id = block_d.get_id().into();
    assert_eq!(block_a_id, block_d.prev_block_id());
    tf.process_block(block_d.clone(), BlockSource::Local).unwrap();

    assert_eq!(block_b_id, tf.best_block_id());

    // Produce block_e and check that reorg happened
    let block_e = tf
        .make_pos_block_builder()
        .with_parent(block_d_id)
        .with_stake_pool_id(pool_2_id)
        .with_kernel_input(UtxoOutPoint::new(block_d_id.into(), 0))
        .with_stake_spending_key(staker_sk_2)
        .with_vrf_key(vrf_sk_2)
        .build(&mut rng);
    let block_e_id = block_e.get_id();
    tf.process_block(block_e.clone(), BlockSource::Local).unwrap();

    assert_eq!(block_d_id, block_e.prev_block_id());
    assert_eq!(block_e_id, tf.best_block_id());

    // Submit block_c that was saved and check that it's valid and reorg happened because it's a denser chain
    tf.chainstate
        .preliminary_headers_check(std::slice::from_ref(block_c.header()))
        .unwrap();
    let block_c = tf.chainstate.preliminary_block_check(block_c).unwrap();
    assert_eq!(block_b_id, block_c.prev_block_id());
    tf.process_block(block_c, BlockSource::Local).unwrap().unwrap();

    assert_eq!(<Id<GenBlock>>::from(block_c_id), tf.best_block_id());
}

// Produce `genesis -> a` chain, where block `a` transfers coins and creates a pool in separate txs.
//
// It's vital to have 2 txs in that order because on disconnect pos undo would be performed first
// and pos::BlockUndo object would be erased. But then when transfer tx is disconnected pos::BlockUndo
// is fetched and checked again, which should work fine and just return None.
//
// Then produce a parallel `genesis -> b -> c` that should trigger a in-memory reorg for block `a`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_pos_tx_with_simple_tx(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let pledge_amount = create_unit_test_config().min_stake_pool_pledge();

    let mut tf = TestFramework::builder(&mut rng).build();
    let genesis_block_id: Id<GenBlock> = tf.genesis().get_id().into();

    // produce block `a` at height 1 and create additional pool
    let transfer_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_block_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(pledge_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let transfer_tx_id = transfer_tx.transaction().get_id();

    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, pledge_amount, vrf_pk);
    let pool_id = PoolId::from_utxo(&UtxoOutPoint::new(transfer_tx_id.into(), 0));
    let stake_pool_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(transfer_tx_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .build();

    tf.make_block_builder()
        .with_transactions(vec![transfer_tx, stake_pool_tx])
        .build_and_process(&mut rng)
        .unwrap();

    // produce block at height 2 that should trigger in memory reorg for block `b`
    let new_chain_block_id = tf.create_chain(&tf.genesis().get_id().into(), 2, &mut rng).unwrap();
    assert_eq!(new_chain_block_id, tf.best_block_id());
}
