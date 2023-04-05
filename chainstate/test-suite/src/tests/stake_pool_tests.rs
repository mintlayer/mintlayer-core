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

use super::helpers::pos::create_stake_pool_data;

use chainstate::BlockSource;
use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_storage::TipStorageTag;
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        timelock::OutputTimeLock,
        tokens::{OutputValue, TokenData, TokenTransfer},
        GenBlock, OutPoint, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use crypto::{
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
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = OutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
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
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
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
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
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
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
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
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                anyonecanspend_address(),
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().token_min_issuance_fee(),
            )))
            .build();
        let tx0_id = tx0.transaction().get_id();
        let token_id = common::chain::tokens::token_id(tx0.transaction()).unwrap();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100..100_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        // stake pool with coin input and transfer tokens with token input
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 1),
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
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
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
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data.clone())))
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
            .build();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InvalidOutputTypeInTx
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
            genesis_tx_output.get(0).unwrap().value().coin_amount().unwrap()
        };
        let genesis_overspend_amount = (genesis_output_amount + Amount::from_atoms(1)).unwrap();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let stake_pool_data = create_stake_pool_data(&mut rng, genesis_overspend_amount, vrf_pk);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
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
fn decommission_from_stake_pool(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = OutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder().add_transaction(tx1).build_and_process().unwrap();

        {
            //try overspend
            let overspend_amount = (amount_to_stake + Amount::from_atoms(1)).unwrap();
            let tx2 = TransactionBuilder::new()
                .add_input(
                    TxInput::new(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                    empty_witness(&mut rng),
                )
                .add_output(TxOutput::DecommissionPool(
                    overspend_amount,
                    anyonecanspend_address(),
                    pool_id,
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
                TxInput::new(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DecommissionPool(
                amount_to_stake,
                anyonecanspend_address(),
                pool_id,
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
        let amount_to_stake = Amount::from_atoms(rng.gen_range(100_000..200_000));
        let stake_pool_data = create_stake_pool_data(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = OutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

        let tx1 = TransactionBuilder::new()
            .add_input(stake_pool_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
            .build();
        let stake_pool_tx_id = tx1.transaction().get_id();

        tf.make_block_builder().add_transaction(tx1).build_and_process().unwrap();

        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(stake_pool_tx_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::DecommissionPool(
                amount_to_stake,
                anyonecanspend_address(),
                pool_id,
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
