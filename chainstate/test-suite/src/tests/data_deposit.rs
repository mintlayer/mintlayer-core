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

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::{
    output_value::OutputValue, signature::inputsig::InputWitness, Destination, OutPointSourceId,
    TxInput, TxOutput, UtxoOutPoint,
};
use common::primitives::{Amount, CoinOrTokenId, Idable};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::CheckTransactionError;

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[trace]
#[case(Seed::from_entropy(), false)]
fn data_deposited_too_large(#[case] seed: Seed, #[case] expect_success: bool) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let deposited_data_len = if expect_success {
            tf.chain_config().data_deposit_max_size()
        } else {
            tf.chain_config().data_deposit_max_size() + 1
        };
        let deposited_data = (0..deposited_data_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(outpoint_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::DataDeposit(deposited_data))
            .build();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build(&mut rng);

        if expect_success {
            let _new_connected_block_index = tf
                .process_block(block.clone(), chainstate::BlockSource::Local)
                .unwrap()
                .unwrap();
        } else {
            let err = tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap_err();

            let expected_err = ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::DataDepositMaxSizeExceeded(
                            deposited_data_len,
                            tf.chain_config().data_deposit_max_size(),
                            tx.transaction().get_id(),
                        ),
                    ),
                ),
            ));

            assert_eq!(err, expected_err);
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true, 1)]
#[trace]
#[case(Seed::from_entropy(), false, 1)]
#[trace]
#[case(Seed::from_entropy(), true, 2)]
#[trace]
#[case(Seed::from_entropy(), false, 2)]
fn data_deposit_insufficient_fee(
    #[case] seed: Seed,
    #[case] expect_success: bool,
    #[case] data_deposit_outputs_count: usize,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let deposited_data_len = tf.chain_config().data_deposit_max_size();
        let deposited_data_len = rng.gen_range(0..deposited_data_len);
        let deposited_data = (0..deposited_data_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let data_fee = if expect_success {
            (tf.chain_config().data_deposit_fee() * data_deposit_outputs_count as u128).unwrap()
        } else {
            (tf.chain_config().data_deposit_fee() * data_deposit_outputs_count as u128)
                .and_then(|v| v - Amount::from_atoms(1))
                .unwrap()
        };

        let tx_with_fee_as_output = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(outpoint_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(data_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_as_output_id = tx_with_fee_as_output.transaction().get_id();

        // First block creates an output with the specified amount
        let _block_index = tf
            .make_block_builder()
            .add_transaction(tx_with_fee_as_output)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let outputs = (0..data_deposit_outputs_count)
            .map(|_| TxOutput::DataDeposit(deposited_data.clone()))
            .collect();
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_with_fee_as_output_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .with_outputs(outputs)
            .build();
        let tx_id = tx.transaction().get_id();

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);

        if expect_success {
            let _new_connected_block_index = tf
                .process_block(block.clone(), chainstate::BlockSource::Local)
                .unwrap()
                .unwrap();
        } else {
            let err = tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap_err();

            let expected_err = ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                    tx_id.into(),
                )),
            );

            assert_eq!(err, expected_err);
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn data_deposit_output_attempt_spend(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let deposited_data_len = tf.chain_config().data_deposit_max_size();
        let deposited_data_len = rng.gen_range(0..deposited_data_len);
        let deposited_data = (0..deposited_data_len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let at_least_data_fee = (tf.chain_config().data_deposit_fee() * 10).unwrap();

        let tx_with_data_as_output = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(outpoint_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                common::chain::output_value::OutputValue::Coin(at_least_data_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::DataDeposit(deposited_data))
            .build();

        // First block creates an output with the specified amount
        let _block_index = tf
            .make_block_builder()
            .add_transaction(tx_with_data_as_output.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_with_data_as_output.transaction().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_data_as_output.transaction().get_id().into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                common::chain::output_value::OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build(&mut rng);

        let err = tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap_err();

        // The data output isn't included in the utxo set, so it can't be spent and will be seen as missing.
        // This is because of how "non-spendable" outputs are handled in the UTXO set, where they're simply ignored.
        let expected_err = ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::MissingOutputOrSpent(UtxoOutPoint::new(
                OutPointSourceId::Transaction(tx_with_data_as_output.transaction().get_id()),
                1,
            )),
        ));

        assert_eq!(err, expected_err);
    })
}
