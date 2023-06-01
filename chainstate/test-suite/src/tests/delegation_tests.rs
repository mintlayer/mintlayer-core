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
    empty_witness, get_output_value, TestFramework, TestStore, TransactionBuilder,
};
use common::chain::{AccountOutPoint, AccountType, DelegationId, PoolId};
use common::{
    chain::{
        timelock::OutputTimeLock, tokens::OutputValue, Destination, OutPointSourceId, TxInput,
        TxOutput, UtxoOutPoint,
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
) -> (PoolId, UtxoOutPoint, UtxoOutPoint) {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let min_stake_pool_pledge =
        tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
    let amount_to_stake =
        Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
    let (stake_pool_data, _) =
        create_stake_pool_data_with_all_reward_to_owner(rng, amount_to_stake, vrf_pk);

    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

    let tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amount_to_stake),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let stake_outpoint =
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
    let transfer_outpoint =
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);

    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (pool_id, stake_outpoint, transfer_outpoint)
}

fn prepare_delegation(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (
    PoolId,
    UtxoOutPoint,
    DelegationId,
    UtxoOutPoint,
    UtxoOutPoint,
) {
    let (pool_id, stake_outpoint, transfer_outpoint) = prepare_stake_pool(rng, tf);

    let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);

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
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
    let transfer_outpoint =
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);

    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (
        pool_id,
        stake_outpoint,
        delegation_id,
        delegation_outpoint,
        transfer_outpoint,
    )
}

fn get_coin_amount_from_outpoint(store: &TestStore, outpoint: &UtxoOutPoint) -> Amount {
    get_output_value(utxo::UtxosStorageRead::get_utxo(store, outpoint).unwrap().unwrap().output())
        .unwrap()
        .coin_amount()
        .unwrap()
}

// Create delegation and check that the data appears in the db but the balance is still none.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, transfer_outpoint) = prepare_stake_pool(&mut rng, &mut tf);
        let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);

        let delegation_spend_destination =
            Destination::PublicKey(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1);

        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                delegation_spend_destination.clone(),
                pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(available_amount),
                Destination::AnyoneCanSpend,
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

// Try to create delegation for unknown pool and get an error
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

// Try creating 2 delegations in 1 tx and get an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk);

        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

        // create pool and 2 transfer utxos
        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let transfer_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 1);

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        // Try to create 2 delegations in 1 transaction
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
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

// Try spending CreateDelegationId output and get an error
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

// Prepare a pool with a delegation.
// Delegate some coins. Check the balance.
// Spend a part of delegated coins. Check the balance.
// Spend the rest of delegation coins. Check that the balance is none but the data still exists.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = available_amount;

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

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
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    0,
                    AccountType::Delegation(delegation_id),
                    (amount_to_spend * 2).unwrap(),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(spend_change), delegation_balance);

        {
            // try spend delegation without increasing nonce
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::Account(AccountOutPoint::new(
                        0,
                        AccountType::Delegation(delegation_id),
                        spend_change,
                    )),
                    empty_witness(&mut rng),
                )
                .add_output(TxOutput::LockThenTransfer(
                    OutputValue::Coin(spend_change),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(1),
                ))
                .build();

            assert_eq!(
                tf.make_block_builder().add_transaction(tx).build_and_process().unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::NonceIsNotIncremental(AccountType::Delegation(
                        delegation_id
                    ))
                ))
            )
        }

        // Spend all delegation balance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    1,
                    AccountType::Delegation(delegation_id),
                    spend_change,
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(spend_change),
                Destination::AnyoneCanSpend,
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

// Prepare a pool with a delegation.
// Delegate some coins. Check the balance.
// Decommission the pool. Check that delegation balance and data exist.
// Spend a part of delegated coins. Check the balance.
// Spend the rest of delegation coins. Check that the delegation is removed entirely.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_then_spend_share_then_cleanup_delegations(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, stake_outpoint, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let amount_to_delegate = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

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
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        let delegation_data = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(
            Some(DelegationData::new(pool_id, Destination::AnyoneCanSpend)),
            delegation_data
        );

        // Spend delegation share and keep the change
        let amount_to_spend = (amount_to_delegate / 3).unwrap();
        let spend_change = (amount_to_delegate - (amount_to_spend * 2).unwrap()).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    0,
                    AccountType::Delegation(delegation_id),
                    (amount_to_spend * 2).unwrap(),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(spend_change), delegation_balance);

        // Spend all delegation balance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    1,
                    AccountType::Delegation(delegation_id),
                    spend_change,
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(spend_change),
                Destination::AnyoneCanSpend,
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

// Prepare a pool with a delegation.
// Delegate some coins. Check the balance.
// Spend entire delegation coins. Check that delegation balance and data exist.
// Decommission the pool. Check that the delegation is removed entirely.
//
// TODO: mintlayer/mintlayer-core/issues/909
#[ignore]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_then_decommission_then_cleanup_delegations(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, stake_outpoint, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let amount_to_delegate = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        let delegate_staking_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        // Spend all delegation balance
        let tx = TransactionBuilder::new()
            .add_input(delegate_staking_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
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
        assert_eq!(
            Some(DelegationData::new(pool_id, Destination::AnyoneCanSpend)),
            delegation_data
        );

        // decommission the pool
        let tx = TransactionBuilder::new()
            .add_input(stake_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
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
