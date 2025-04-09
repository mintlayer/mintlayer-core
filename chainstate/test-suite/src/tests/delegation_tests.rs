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

use chainstate::{BlockError, ChainstateError, ConnectTransactionError, IOPolicyError};
use chainstate_storage::Transactional;
use chainstate_test_framework::{
    create_stake_pool_data_with_all_reward_to_staker, empty_witness, get_output_value,
    TestFramework, TestStore, TransactionBuilder,
};
use chainstate_types::TipStorageTag;
use common::{
    chain::{
        config::create_unit_test_config,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            DestinationSigError,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        AccountNonce, AccountOutPoint, AccountSpending, AccountType, DelegationId, Destination,
        OutPointSourceId, PoolId, SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::{DelegationData, PoSAccountingStorageRead};
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::error::{InputCheckError, ScriptError};

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
        create_stake_pool_data_with_all_reward_to_staker(rng, amount_to_stake, vrf_pk);

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

    tf.make_block_builder()
        .add_transaction(tx)
        .build_and_process(&mut *rng)
        .unwrap();

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

    tf.make_block_builder()
        .add_transaction(tx)
        .build_and_process(&mut *rng)
        .unwrap();

    (
        pool_id,
        stake_outpoint,
        delegation_id,
        delegation_outpoint,
        transfer_outpoint,
    )
}

fn get_coin_amount_from_outpoint(store: &TestStore, outpoint: &UtxoOutPoint) -> Amount {
    let db_tx = store.transaction_ro().unwrap();
    get_output_value(utxo::UtxosStorageRead::get_utxo(&db_tx, outpoint).unwrap().unwrap().output())
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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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

        let res = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap_err();
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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
        let tx_id = tx.transaction().get_id();

        let res = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleDelegationCreated,
                    tx_id.into()
                )
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
            .add_input(delegation_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::ZERO),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let res = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(delegation_outpoint)
            ))
        );
    });
}

// Try spending DelegateStaking output and get an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_delegate_staking_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = available_amount;

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();
        let delegate_staking_outpoint = UtxoOutPoint::new(tx.transaction().get_id().into(), 0);

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                delegate_staking_outpoint.clone().into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::ZERO),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let res = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(delegate_staking_outpoint)
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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(
                        delegation_id,
                        (amount_to_spend * 2).unwrap(),
                    ),
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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
                        AccountNonce::new(0),
                        AccountSpending::DelegationBalance(delegation_id, spend_change),
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
                tf.make_block_builder()
                    .add_transaction(tx)
                    .build_and_process(&mut rng)
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::NonceIsNotIncremental(
                        AccountType::Delegation(delegation_id),
                        AccountNonce::new(1),
                        AccountNonce::new(0),
                    )
                ))
            )
        }

        {
            // try spend delegation skipping values of nonce
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::Account(AccountOutPoint::new(
                        AccountNonce::new(2),
                        AccountSpending::DelegationBalance(delegation_id, spend_change),
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
                tf.make_block_builder()
                    .add_transaction(tx)
                    .build_and_process(&mut rng)
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::NonceIsNotIncremental(
                        AccountType::Delegation(delegation_id),
                        AccountNonce::new(1),
                        AccountNonce::new(2),
                    )
                ))
            )
        }

        // Spend all delegation balance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(1),
                    AccountSpending::DelegationBalance(delegation_id, spend_change),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(spend_change),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
// Spend the rest of delegation coins. Check that the delegation was not removed.
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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        // decommission the pool
        let staker_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_data(&tf.storage, pool_id)
                .unwrap()
                .unwrap()
                .staker_balance()
                .unwrap();
        let tx = TransactionBuilder::new()
            .add_input(stake_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(staker_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(
                        delegation_id,
                        (amount_to_spend * 2).unwrap(),
                    ),
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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
                    AccountNonce::new(1),
                    AccountSpending::DelegationBalance(delegation_id, spend_change),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(spend_change),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
        assert!(delegation_data.is_some());
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
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

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

// Create a pool, create delegation id and delegate staking in different transactions in the same blocks
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_and_delegation_and_delegate_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx1_source_id = OutPointSourceId::Transaction(tx1.transaction().get_id());
        let tx_1_kernel0_outpoint = UtxoOutPoint::new(tx1_source_id, 1);

        let delegation_id = pos_accounting::make_delegation_id(&tx_1_kernel0_outpoint);
        let tx2 = TransactionBuilder::new()
            .add_input(tx_1_kernel0_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx2_source_id = OutPointSourceId::Transaction(tx2.transaction().get_id());

        let tx3 = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(tx2_source_id, 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(amount_to_stake, delegation_id))
            .build();

        tf.make_block_builder()
            .with_transactions(vec![tx1, tx2, tx3])
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.chainstate.get_stake_delegation_balance(delegation_id).unwrap(),
            Some(amount_to_stake)
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_spend_share(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, transfer_outpoint) = prepare_stake_pool(&mut rng, &mut tf);
        let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);

        let (delegation_sk, delegation_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let create_delegation_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateDelegationId(
                Destination::PublicKey(delegation_pk.clone()),
                pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(available_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let create_delegation_tx_id = create_delegation_tx.transaction().get_id();

        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(create_delegation_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::DelegateStaking(available_amount, delegation_id))
            .build();

        tf.make_block_builder()
            .with_transactions(vec![create_delegation_tx, delegate_staking_tx])
            .build_and_process(&mut rng)
            .unwrap();

        let spend_share_tx_no_signature = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, available_amount),
                )),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(available_amount),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        // Try to spend share with no input signature
        let result = tf
            .make_block_builder()
            .add_transaction(spend_share_tx_no_signature.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let inputs_utxos = [None];
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Try to spend share with wrong signature
        let tx = {
            let tx = spend_share_tx_no_signature.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &inputs_utxos_refs,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(tx, vec![InputWitness::Standard(account_sig)]).unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Lock with proper keys
        let tx = {
            let tx = spend_share_tx_no_signature.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &delegation_sk,
                Default::default(),
                Destination::PublicKey(delegation_pk),
                &tx,
                &inputs_utxos_refs,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(tx, vec![InputWitness::Standard(account_sig)]).unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

// Prepare a pool with delegation.
// Delegate some coins.
// In a single tx delegate more coins and spend original balance + some new coins in a single input
// which has a value greater than current balance.
// Check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_and_spend_share_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = Amount::from_atoms(1000);
        let amount_to_delegate = (available_amount / 2).unwrap();
        let change = (available_amount - amount_to_delegate).unwrap();

        // Delegate staking
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let original_delegation_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id,
            )
            .unwrap()
            .unwrap();
        assert_eq!(amount_to_delegate, original_delegation_balance);

        // try spending in an single input original balance and a part of newly delegated amount
        let amount_to_spend = (original_delegation_balance
            + Amount::from_atoms(rng.gen_range(1..=change.into_atoms())))
        .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, amount_to_spend),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(change, delegation_id))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);
        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Prepare a pool with delegation.
// Delegate some coins.
// In a single tx delegate more coins and spend original balance + some new coins using 2 inputs
// which individually aren't greater than original balance.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_and_spend_share_same_tx_no_overspend_per_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = (available_amount / 2).unwrap();
        let change = (available_amount - amount_to_delegate).unwrap();

        // Delegate staking
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let original_delegation_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id,
            )
            .unwrap()
            .unwrap();
        assert_eq!(amount_to_delegate, original_delegation_balance);

        // try spending in an single input original balance and newly delegated amount
        let amount_to_spend_per_input = Amount::from_atoms(
            rng.gen_range(
                original_delegation_balance.into_atoms()
                    ..=(original_delegation_balance + change).unwrap().into_atoms(),
            ) / 2,
        );

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, amount_to_spend_per_input),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(1),
                    AccountSpending::DelegationBalance(delegation_id, amount_to_spend_per_input),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin((original_delegation_balance + Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .add_output(TxOutput::DelegateStaking(change, delegation_id))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Prepare a pool with delegation.
// Delegate some coins.
// In one tx spend original balance + some new coins. In second tx delegate new coins.
// Check it's an error even though if both txs are applied the block would be valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_and_spend_share_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = (available_amount / 2).unwrap();

        // Delegate staking
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let original_delegation_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id,
            )
            .unwrap()
            .unwrap();
        assert_eq!(amount_to_delegate, original_delegation_balance);

        // try spending more the original balance but including new delegation amount
        let amount_to_spend = Amount::from_atoms(rng.gen_range(
            original_delegation_balance.into_atoms()
                ..=(original_delegation_balance + amount_to_delegate).unwrap().into_atoms(),
        ));

        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, amount_to_spend),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx1_id = tx1.transaction().get_id();

        let tx2 = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        let res = tf
            .make_block_builder()
            .with_transactions(vec![tx1, tx2])
            .build_and_process(&mut rng);
        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx1_id.into()
                )
            ))
        );
    });
}

// Prepare a pool with delegation.
// Delegate some coins.
// Try spend from delegation using 2 inputs, which individually are less than balance
// but their sum if greater than balance.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_overspend_delegation_single_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = available_amount;

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap()
        .unwrap()
        .into_atoms();
        assert_eq!(amount_to_delegate, Amount::from_atoms(delegation_balance));

        // try overspend delegation balance, but each spending individually must be valid
        let to_spend_1 = rng.gen_range(1..=delegation_balance);
        let to_spend_2 = rng.gen_range(delegation_balance - to_spend_1 + 1..=delegation_balance);
        assert!(
            (to_spend_1 <= delegation_balance)
                && (to_spend_2 <= delegation_balance)
                && (to_spend_1 + to_spend_2 > delegation_balance)
        );

        let to_spend_1 = Amount::from_atoms(to_spend_1);
        let to_spend_2 = Amount::from_atoms(to_spend_2);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, to_spend_1),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(1),
                    AccountSpending::DelegationBalance(delegation_id, to_spend_2),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(to_spend_1),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(to_spend_2),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Prepare a pool with delegation.
// Delegate some coins.
// Try spend from delegation using 2 transactions to check that delegation balance across
// transactions is validated.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_overspend_delegation_multiple_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = available_amount;

        // Delegate staking
        let tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(amount_to_delegate, delegation_balance);

        // try overspend delegation balance in second tx
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, delegation_balance),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(delegation_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(1)),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx_id = tx2.transaction().get_id();

        let res = tf
            .make_block_builder()
            .with_transactions(vec![tx1, tx2])
            .build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_and_spend_share_same_block_multiple_delegations(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, _, delegation_id_1, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = (available_amount / 2).unwrap();
        let change = (available_amount - amount_to_delegate).unwrap();

        // Create second delegation and delegate coins to both
        let delegation_id_2 = pos_accounting::make_delegation_id(&transfer_outpoint);
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(
                amount_to_delegate,
                delegation_id_1,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        let amount_to_delegate = (change / 2).unwrap();
        let change = (change - amount_to_delegate).unwrap();
        let delegate_staking_tx_2 = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(
                amount_to_delegate,
                delegation_id_2,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_2_id = delegate_staking_tx_2.transaction().get_id();

        tf.make_block_builder()
            .with_transactions(vec![delegate_staking_tx, delegate_staking_tx_2])
            .build_and_process(&mut rng)
            .unwrap();

        let original_delegation_balance_1 =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id_1,
            )
            .unwrap()
            .unwrap();
        let original_delegation_balance_2 =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id_2,
            )
            .unwrap()
            .unwrap();

        // try spending more from delegation_1 than the original balance but including new delegation amount
        let amount_to_spend_per_input = Amount::from_atoms(
            rng.gen_range(
                original_delegation_balance_1.into_atoms()
                    ..=(original_delegation_balance_1 + change).unwrap().into_atoms(),
            ) / 2,
        );

        assert!((amount_to_spend_per_input * 2).unwrap() > original_delegation_balance_1);

        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id_1, amount_to_spend_per_input),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(1),
                    AccountSpending::DelegationBalance(delegation_id_1, amount_to_spend_per_input),
                )),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(
                        delegation_id_2,
                        original_delegation_balance_2,
                    ),
                )),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_spend_per_input),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        let tx_id_1 = tx1.transaction().get_id();

        let tx2 = TransactionBuilder::new()
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_2_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(change, delegation_id_1))
            .build();

        let res = tf
            .make_block_builder()
            .with_transactions(vec![tx1, tx2])
            .build_and_process(&mut rng);
        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id_1.into()
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_then_delegate_staking_and_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (pool_id, stake_outpoint, delegation_id, _, transfer_outpoint) =
            prepare_delegation(&mut rng, &mut tf);
        let amount_to_delegate = (get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint)
            - Amount::from_atoms(1))
        .unwrap();

        // Delegate staking
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(Some(amount_to_delegate), delegation_balance);

        // decommission the pool
        let staker_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_data(&tf.storage, pool_id)
                .unwrap()
                .unwrap()
                .staker_balance()
                .unwrap();
        let decommission_pool_tx = TransactionBuilder::new()
            .add_input(stake_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(staker_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        tf.make_block_builder()
            .add_transaction(decommission_pool_tx)
            .build_and_process(&mut rng)
            .unwrap();

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

        // Delegate more after the pool was decommissioned
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(delegate_staking_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DelegateStaking(
                Amount::from_atoms(1),
                delegation_id,
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(
            amount_to_delegate + Amount::from_atoms(1),
            delegation_balance
        );

        // Reorg to undo all the operations
        let old_tip = tf.best_block_id();
        let new_tip = tf.create_chain(&tf.chain_config().genesis_block_id(), 10, &mut rng).unwrap();
        assert_ne!(old_tip, new_tip);
        assert_eq!(new_tip, tf.best_block_id());
    });
}

// Create genesis pool that has non-zero delegation reward.
// In the same block create a delegation and delegate some coins to genesis pool.
// Using genesis pool generate a block, distributing reward to newly created delegation.
// Create alternative chain to trigger a reorg. It shouldn't fail.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_same_pool_as_staking(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staker_sk, staker_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let stake_pool_pledge = create_unit_test_config().min_stake_pool_pledge();
    let stake_pool_data = StakePoolData::new(
        stake_pool_pledge,
        Destination::PublicKey(staker_pk),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(500).unwrap(),
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

    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.clone())
        .with_initial_time_since_genesis(target_block_time.as_secs())
        .build();

    let genesis_mint_outpoint = UtxoOutPoint::new(tf.chain_config().genesis_block_id().into(), 0);
    let create_delegation_tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(genesis_mint_outpoint.clone()),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            genesis_pool_id,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(mint_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let create_delegation_tx_id = create_delegation_tx.transaction().get_id();
    let delegation_id = pos_accounting::make_delegation_id(&genesis_mint_outpoint);

    let delegate_staking_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(create_delegation_tx_id.into(), 1),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::DelegateStaking(mint_amount, delegation_id))
        .build();

    // Create block with delegation to genesis pool
    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staker_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .with_transactions(vec![create_delegation_tx, delegate_staking_tx])
        .build_and_process(&mut rng)
        .unwrap();

    // Create alternative chain to trigger reorg
    tf.create_chain_pos(
        &mut rng,
        &tf.chain_config().genesis_block_id(),
        2,
        genesis_pool_id,
        &staker_sk,
        &vrf_sk,
    )
    .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_and_spend_with_multiple_inputs_in_single_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, _, delegation_id, _, transfer_outpoint) = prepare_delegation(&mut rng, &mut tf);
        let available_amount = get_coin_amount_from_outpoint(&tf.storage, &transfer_outpoint);
        let amount_to_delegate = (available_amount / 2).unwrap();
        let change = (available_amount - amount_to_delegate).unwrap();

        // Delegate staking
        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let delegate_staking_tx_id = delegate_staking_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let original_delegation_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
                &tf.storage,
                delegation_id,
            )
            .unwrap()
            .unwrap();
        assert_eq!(amount_to_delegate, original_delegation_balance);

        // Spend entire delegated amount in multiple inputs
        let atoms_per_input = test_utils::split_value(&mut rng, amount_to_delegate.into_atoms());
        let mut tx_builder = TransactionBuilder::new();
        for (i, atoms) in atoms_per_input.iter().enumerate() {
            tx_builder = tx_builder.add_input(
                TxInput::from_account(
                    AccountNonce::new(i as u64),
                    AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(*atoms)),
                ),
                empty_witness(&mut rng),
            );
        }

        let tx = tx_builder
            .add_input(
                UtxoOutPoint::new(delegate_staking_tx_id.into(), 1).into(),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let delegation_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
            &tf.storage,
            delegation_id,
        )
        .unwrap();
        assert_eq!(None, delegation_balance);
    });
}
