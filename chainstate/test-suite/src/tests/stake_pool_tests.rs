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

use chainstate::BlockSource;
use chainstate::{BlockError, ChainstateError, ConnectTransactionError, IOPolicyError};
use chainstate_storage::TipStorageTag;
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, get_output_value, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            TransactionSigError,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{TokenData, TokenTransfer},
        Destination, GenBlock, OutPointSourceId, SignedTransaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Id, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::PoSAccountingStorageRead;
use rstest::rstest;
use test_utils::{
    nft_utils::random_token_issuance,
    random::{make_seedable_rng, Seed},
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_basic(#[case] seed: Seed) {
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

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));

        let pool_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
                .unwrap()
                .unwrap();
        assert_eq!(amount_to_stake, pool_balance);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_spend_coin_same_tx(#[case] seed: Seed) {
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

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                anyonecanspend_address(),
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_issue_tokens_same_tx(#[case] seed: Seed) {
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

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                random_token_issuance(tf.chainstate.get_chain_config().clone(), &mut rng).into(),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().token_min_issuance_fee(),
            )))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_transfer_tokens_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create a tx with coins utxo and token issuance utxo
        let token_issuance_data =
            random_token_issuance(tf.chainstate.get_chain_config().clone(), &mut rng);
        let amount_to_issue = token_issuance_data.amount_to_issue;
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                token_issuance_data.into(),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().token_min_issuance_fee(),
            )))
            .build();
        let tx0_id = tx0.transaction().get_id();
        let token_id = common::chain::tokens::make_token_id(tx0.transaction().inputs()).unwrap();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_owner(&mut rng, amount_to_stake, vrf_pk);
        let outpoint0 = UtxoOutPoint::new(OutPointSourceId::Transaction(tx0_id), 0);
        let pool_id = pos_accounting::make_pool_id(&outpoint0);

        // stake pool with coin input and transfer tokens with token input
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx0_id), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id,
                    amount: amount_to_issue,
                })
                .into(),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let best_block_index = tf
            .make_block_builder()
            .with_transactions(vec![tx0, tx1])
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*best_block_index.block_id())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_twice(#[case] seed: Seed) {
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

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data.clone()),
            ))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultiplePoolCreated,
                    tx_id.into()
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_overspend(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id().into();

        let genesis_output_amount = {
            let genesis_outputs = tf.outputs_from_genblock(genesis_id);
            assert_eq!(genesis_outputs.len(), 1);
            let genesis_tx_output =
                genesis_outputs.get(&OutPointSourceId::BlockReward(genesis_id)).unwrap();
            assert_eq!(genesis_tx_output.len(), 1);
            get_output_value(&genesis_tx_output[0]).unwrap().coin_amount().unwrap()
        };
        let genesis_overspend_amount = (genesis_output_amount + Amount::from_atoms(1)).unwrap();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_owner(
            &mut rng,
            genesis_overspend_amount,
            vrf_pk,
        );
        let genesis_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id), 0);
        let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(
                    genesis_output_amount,
                    genesis_overspend_amount
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_not_enough_pledge(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id().into();
        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id), 0);
        let pool_id = pos_accounting::make_pool_id(&genesis_outpoint);

        let min_pledge = tf.chainstate.get_chain_config().min_stake_pool_pledge();

        // invalid case
        let amount_to_stake = Amount::from_atoms(rng.gen_range(1..min_pledge.into_atoms()));
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_owner(
            &mut rng,
            amount_to_stake,
            vrf_pk.clone(),
        );
        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::NotEnoughPledgeToCreateStakePool(
                    tx_id,
                    amount_to_stake,
                    min_pledge
                )
            ))
        );

        // valid case
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_owner(&mut rng, min_pledge, vrf_pk);
        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_stake_pool(#[case] seed: Seed) {
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

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder().add_transaction(tx1).build_and_process().unwrap();

        {
            //try overspend
            let overspend_amount = (amount_to_stake + Amount::from_atoms(1)).unwrap();
            let tx2 = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                    empty_witness(&mut rng),
                )
                .add_output(TxOutput::LockThenTransfer(
                    OutputValue::Coin(overspend_amount),
                    anyonecanspend_address(),
                    OutputTimeLock::ForBlockCount(1),
                ))
                .build();

            let result =
                tf.make_block_builder().add_transaction(tx2).build_and_process().unwrap_err();

            assert_eq!(
                result,
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::AttemptToPrintMoney(amount_to_stake, overspend_amount)
                ))
            );
        }

        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_stake),
                anyonecanspend_address(),
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx2).build_and_process().unwrap();

        let pool_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
                .unwrap();
        assert!(pool_balance.is_none());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_stake_pool_same_block(#[case] seed: Seed) {
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

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder().add_transaction(tx1).build_and_process().unwrap();

        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_stake),
                anyonecanspend_address(),
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx2).build_and_process().unwrap();

        let pool_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
                .unwrap();
        assert!(pool_balance.is_none());
    });
}

// check that `CreateStakePool` output can be decommissioned only with `decommission_key`
// and not `staking_key`
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_stake_pool_with_staker_key(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (staking_sk, staking_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (decommission_sk, decommission_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));

        let stake_pool_data = StakePoolData::new(
            amount_to_stake,
            Destination::PublicKey(staking_pk.clone()),
            vrf_pk,
            Destination::PublicKey(decommission_pk.clone()),
            PerThousand::new_from_rng(&mut rng),
            Amount::ZERO,
        );

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx1).build_and_process().unwrap();

        let (best_block_source_id, best_block_utxos) =
            tf.outputs_from_genblock(tf.best_block_id()).into_iter().next().unwrap();
        let inputs_utxos = best_block_utxos.iter().map(Some).collect::<Vec<_>>();

        {
            // sign with staking key
            let tx2 = {
                let tx = TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(best_block_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::LockThenTransfer(
                        OutputValue::Coin(amount_to_stake),
                        anyonecanspend_address(),
                        OutputTimeLock::ForBlockCount(1),
                    ))
                    .build()
                    .transaction()
                    .clone();

                let staking_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                    &staking_sk,
                    Default::default(),
                    Destination::PublicKey(staking_pk),
                    &tx,
                    &inputs_utxos,
                    0,
                )
                .unwrap();

                SignedTransaction::new(tx, vec![InputWitness::Standard(staking_sig)]).unwrap()
            };

            let result =
                tf.make_block_builder().add_transaction(tx2).build_and_process().unwrap_err();

            assert_eq!(
                result,
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::SignatureVerificationFailed(
                        TransactionSigError::SignatureVerificationFailed
                    )
                ))
            );
        }

        let tx2 = {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(best_block_source_id, 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::LockThenTransfer(
                    OutputValue::Coin(amount_to_stake),
                    anyonecanspend_address(),
                    OutputTimeLock::ForBlockCount(1),
                ))
                .build()
                .transaction()
                .clone();

            let decommission_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &decommission_sk,
                Default::default(),
                Destination::PublicKey(decommission_pk),
                &tx,
                &inputs_utxos,
                0,
            )
            .unwrap();

            SignedTransaction::new(tx, vec![InputWitness::Standard(decommission_sig)]).unwrap()
        };

        tf.make_block_builder()
            .add_transaction(tx2)
            .build_and_process()
            .unwrap()
            .unwrap();
    });
}
