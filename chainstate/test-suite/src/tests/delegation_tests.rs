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

use super::helpers::pos::create_stake_pool_data_with_all_reward_to_owner;

use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_storage::TipStorageTag;
use chainstate_test_framework::{
    empty_witness, get_output_value, TestFramework, TransactionBuilder,
};
use common::chain::{DelegationId, PoolId};
use common::{
    chain::{
        timelock::OutputTimeLock, tokens::OutputValue, Destination, OutPoint, OutPointSourceId,
        TxOutput,
    },
    primitives::{Amount, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::{CryptoRng, Rng},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::{DelegationData, PoSAccountingStorageRead};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

fn prepare_stake_pool(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (PoolId, OutPoint, OutPoint) {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let amount_to_stake = Amount::from_atoms(rng.gen_range(1000..200_000));
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_owner(rng, amount_to_stake, vrf_pk);

    let genesis_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

    let tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(Box::new(stake_pool_data)))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amount_to_stake),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let stake_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
    let transfer_outpoint =
        OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);

    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (pool_id, stake_outpoint, transfer_outpoint)
}

fn prepare_delegation(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (PoolId, OutPoint, DelegationId, OutPoint, OutPoint) {
    let (pool_id, stake_outpoint, transfer_outpoint) = prepare_stake_pool(rng, tf);

    let available_amount = get_output_value(
        utxo::UtxosStorageRead::get_utxo(&tf.storage, &transfer_outpoint)
            .unwrap()
            .unwrap()
            .output(),
    )
    .unwrap()
    .coin_amount()
    .unwrap();

    let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);
    let tx = TransactionBuilder::new()
        .add_input(transfer_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            pool_id,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let delegation_outpoint =
        OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
    let transfer_outpoint =
        OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);

    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (
        pool_id,
        stake_outpoint,
        delegation_id,
        delegation_outpoint,
        transfer_outpoint,
    )
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, transfer_outpoint) = prepare_stake_pool(&mut rng, &mut tf);
        let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);

        let delegation_spend_destination =
            Destination::PublicKey(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1);

        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                delegation_spend_destination.clone(),
                pool_id,
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert!(delegation_balance.is_none());

        let expected_delegation_data = DelegationData::new(pool_id, delegation_spend_destination);
        let delegation_data = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(
            &tf.storage,
            delegation_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(expected_delegation_data, delegation_data);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_unknown_pool(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, transfer_outpoint) = prepare_stake_pool(&mut rng, &mut tf);

        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                PoolId::new(H256::random_using(&mut rng)),
            ))
            .build();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process().unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::PoSAccountingError(
                    pos_accounting::Error::DelegationCreationFailedPoolDoesNotExist
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let amount_to_stake = Amount::from_atoms(rng.gen_range(1000..200_000));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk);

        let genesis_outpoint = OutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

        // create pool and 2 transfer utxos
        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(Box::new(stake_pool_data)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let transfer_outpoint1 =
            OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);
        let transfer_outpoint2 =
            OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 2);

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        // Try to create 2 delegations in 1 transaction
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint1.into(), empty_witness(&mut rng))
            .add_input(transfer_outpoint2.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .build();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process().unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InvalidOutputTypeInTx
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_create_delegation_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, _, delegation_outpoint, _) = prepare_delegation(&mut rng, &mut tf);

        let tx = TransactionBuilder::new()
            .add_input(delegation_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::ZERO),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process().unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_output_value(
            utxo::UtxosStorageRead::get_utxo(&tf.storage, &transfer_outpoint)
                .unwrap()
                .unwrap()
                .output(),
        )
        .unwrap()
        .coin_amount()
        .unwrap();
        let amount_to_delegate = available_amount;

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        let delegate_staking_outpoint =
            OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        // Spend delegation share and keep the change
        let amount_to_spend = (amount_to_delegate / 3).unwrap();
        let spend_change = (amount_to_delegate - (amount_to_spend * 2).unwrap()).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(delegate_staking_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(spend_change, delegation_id))
            .add_output(TxOutput::SpendShareFromDelegation(
                amount_to_spend,
                Destination::AnyoneCanSpend,
                delegation_id,
                OutputTimeLock::ForBlockCount(1),
            ))
            .add_output(TxOutput::SpendShareFromDelegation(
                amount_to_spend,
                Destination::AnyoneCanSpend,
                delegation_id,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        let delegate_staking_outpoint =
            OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(spend_change), delegation_balance);

        // Spend all delegation balance
        let tx = TransactionBuilder::new()
            .add_input(delegate_staking_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::SpendShareFromDelegation(
                spend_change,
                Destination::AnyoneCanSpend,
                delegation_id,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert!(delegation_balance.is_none());

        let delegation_data = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(
            &tf.storage,
            delegation_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            delegation_data,
            DelegationData::new(pool_id, Destination::AnyoneCanSpend)
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegation_cleanup(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, stake_outpoint, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let amount_to_delegate = get_output_value(
            utxo::UtxosStorageRead::get_utxo(&tf.storage, &transfer_outpoint)
                .unwrap()
                .unwrap()
                .output(),
        )
        .unwrap()
        .coin_amount()
        .unwrap();

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        let delegate_staking_outpoint =
            OutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        // decommission the pool
        let tx = TransactionBuilder::new()
            .add_input(stake_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DecommissionPool(
                Amount::from_atoms(1),
                Destination::AnyoneCanSpend,
                pool_id,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        // Spend all delegation share
        let tx = TransactionBuilder::new()
            .add_input(delegate_staking_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::SpendShareFromDelegation(
                amount_to_delegate,
                Destination::AnyoneCanSpend,
                delegation_id,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert!(delegation_balance.is_none());

        let delegation_data = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert!(delegation_data.is_none());
    });
}
