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
use chainstate::{BlockSource, CheckBlockError};
use chainstate_test_framework::{
    anyonecanspend_address, create_stake_pool_data_with_all_reward_to_staker, empty_witness,
    get_output_value, TestFramework, TransactionBuilder,
};
use chainstate_types::TipStorageTag;
use common::primitives::BlockHeight;
use common::{
    chain::{
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            DestinationSigError,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::TokenIssuance,
        AccountCommand, AccountNonce, Destination, GenBlock, OutPointSourceId, PoolId,
        SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, CoinOrTokenId, Id, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::PoSAccountingStorageRead;
use randomness::Rng;
use rstest::rstest;
use test_utils::{
    nft_utils::random_token_issuance_v1,
    random::{make_seedable_rng, Seed},
};
use tx_verifier::error::{InputCheckError, ScriptError};

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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&stake_pool_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

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

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                random_token_issuance_v1(
                    tf.chain_config().as_ref(),
                    Destination::AnyoneCanSpend,
                    &mut rng,
                ),
            ))))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_mint_tokens_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create a tx with coins utxo and token issuance
        let amount_to_mint = Amount::from_atoms(100);
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
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                random_token_issuance_v1(
                    tf.chain_config().as_ref(),
                    Destination::AnyoneCanSpend,
                    &mut rng,
                ),
            ))))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_stake),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero()),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx0_id = tx0.transaction().get_id();
        let token_id = common::chain::make_token_id(
            tf.chain_config(),
            BlockHeight::zero(),
            tx0.transaction().inputs(),
        )
        .unwrap();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
        let outpoint0 = UtxoOutPoint::new(OutPointSourceId::Transaction(tx0_id), 1);
        let pool_id = PoolId::from_utxo(&outpoint0);

        // stake pool with coin input and transfer tokens with token input
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx0_id), 1),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx0_id), 2),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
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
            .build_and_process(&mut rng)
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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
        let genesis_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

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

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

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
fn stake_pool_twice_two_blocks(#[case] seed: Seed) {
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
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(genesis_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data.clone()),
            ))
            .build();
        tf.make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .unwrap();

        let tx2 = TransactionBuilder::new()
            .add_input(genesis_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let result = tf.make_block_builder().add_transaction(tx2).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(genesis_outpoint)
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_twice_two_txs(#[case] seed: Seed) {
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
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(genesis_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data.clone()),
            ))
            .build();

        let tx2 = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let block = tf.make_block_builder().with_transactions(vec![tx1, tx2]).build(&mut rng);
        let block_id = block.get_id();
        let result = tf.process_block(block, BlockSource::Local);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::DuplicateInputInBlock(block_id)
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
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            genesis_overspend_amount,
            vrf_pk,
        );
        let genesis_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id), 0);
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::Coin
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
fn stake_pool_not_enough_pledge(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id().into();
        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id), 0);
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let min_pledge = tf.chainstate.get_chain_config().min_stake_pool_pledge();

        // invalid case
        let amount_to_stake = Amount::from_atoms(rng.gen_range(1..min_pledge.into_atoms()));
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(
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

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, min_pledge, vrf_pk);
        let tx = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .unwrap();

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
            let tx2_id = tx2.transaction().get_id();
            let result = tf
                .make_block_builder()
                .add_transaction(tx2)
                .build_and_process(&mut rng)
                .unwrap_err();

            assert_eq!(
                result,
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::Coin
                        ),
                        tx2_id.into()
                    )
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

        tf.make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .unwrap();

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
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = PoolId::from_utxo(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .unwrap();

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

        tf.make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .unwrap();

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
        let pool_id = PoolId::from_utxo(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .unwrap();

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
                    &mut rng,
                )
                .unwrap();

                SignedTransaction::new(tx, vec![InputWitness::Standard(staking_sig)]).unwrap()
            };

            let result = tf
                .make_block_builder()
                .add_transaction(tx2)
                .build_and_process(&mut rng)
                .unwrap_err();

            assert_eq!(
                result,
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                    ))
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
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(tx, vec![InputWitness::Standard(decommission_sig)]).unwrap()
        };

        tf.make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    });
}
