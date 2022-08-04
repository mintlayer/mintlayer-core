// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Sinitsyn

use crate::detail::{
    tests::{test_framework::TransactionBuilder, TestFramework, *},
    transaction_verifier::error::ConnectTransactionError,
};
use common::{
    chain::{tokens::OutputValue, OutPointSourceId, Spender, Transaction, TxInput, TxOutput},
    primitives::{Amount, Id},
};

// Process a block where the second transaction uses the first one as input.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = tx1        | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_output_in_the_same_block(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);
        let second_tx = tx_from_tx(&first_tx, rng.gen_range(1000..2000));

        let block = tf.make_block_builder().with_transactions(vec![first_tx, second_tx]).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

// The order of transactions is important, so in the following case block processing should result
// in an error.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = tx2        | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_output_in_the_same_block_invalid_order(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);
        let second_tx = tx_from_tx(&first_tx, rng.gen_range(1000..2000));

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![second_tx, first_tx])
                .build_and_process()
                .unwrap_err(),
            BlockError::StateUpdateFailed(ConnectTransactionError::MissingOutputOrSpent)
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Try to use the transaction output twice in one block.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = tx1        | |
// | +-------------------+ |
// |                       |
// | +-------tx-3--------+ |
// | |input = tx1        | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn double_spend_tx_in_the_same_block(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);
        let second_tx = tx_from_tx(&first_tx, rng.gen_range(1000..2000));
        let third_tx = tx_from_tx(&first_tx, rng.gen_range(1000..2000));

        let block = tf
            .make_block_builder()
            .with_transactions(vec![first_tx, second_tx, third_tx])
            .build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::DuplicateInputInBlock(block_id)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Try to use an output twice in different blocks.
//
// Genesis -> b1 -> b2.
//
// +--Block-1--------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = genesis    | |
// | +-------------------+ |
// +-----------------------+
//
// +--Block-2--------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = genesis    | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn double_spend_tx_in_another_block(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);
        let first_block = tf.make_block_builder().add_transaction(first_tx.clone()).build();
        let first_block_id = first_block.get_id();
        tf.process_block(first_block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), first_block_id);

        let tx2_output_value = rng.gen_range(100_000..200_000);
        let second_tx = tx_from_genesis(tf.genesis(), &mut rng, tx2_output_value);
        let second_block = tf.make_block_builder().add_transaction(second_tx).build();
        assert_eq!(
            tf.process_block(second_block, BlockSource::Local).unwrap_err(),
            BlockError::StateUpdateFailed(ConnectTransactionError::DoubleSpendAttempt(
                Spender::RegularInput(first_tx.get_id())
            ))
        );
        assert_eq!(tf.best_block_id(), first_block_id);
    });
}

// Try to process a block where the second transaction's input is more then first output.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = tx1        | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn overspend_single_output(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(1000..2000);
        let tx2_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);
        let second_tx = tx_from_tx(&first_tx, tx2_output_value);

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![first_tx, second_tx])
                .build_and_process()
                .unwrap_err(),
            BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(
                Amount::from_atoms(tx1_output_value),
                Amount::from_atoms(tx2_output_value)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Check that it is impossible to overspend the input using several outputs, even if each of the
// individual outputs spends less than input.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn overspend_multiple_outputs(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);

        let tx1_output_value = rng.gen_range(1000..2000);
        let tx1 = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);

        let tx2_output_value = tx1_output_value - 1;
        let tx2_output = TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(tx2_output_value)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        );
        let tx2 = TransactionBuilder::new()
            .add_input(TxInput::new(
                tx1.get_id().into(),
                0,
                InputWitness::NoSignature(None),
            ))
            .with_outputs(vec![tx2_output.clone(), tx2_output])
            .build();

        assert_eq!(
            tf.make_block_builder()
                .with_transactions(vec![tx1, tx2])
                .build_and_process()
                .unwrap_err(),
            BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(
                Amount::from_atoms(tx1_output_value),
                Amount::from_atoms(tx2_output_value * 2)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Try to use the transaction input twice in one block.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = tx1        | |
// | |input = tx1        | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn duplicate_input_in_the_same_tx(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);

        let input = TxInput::new(first_tx.get_id().into(), 0, InputWitness::NoSignature(None));
        let second_tx = TransactionBuilder::new()
            .add_input(input.clone())
            .add_input(input)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();
        let second_tx_id = second_tx.get_id();

        let block = tf.make_block_builder().with_transactions(vec![first_tx, second_tx]).build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::DuplicateInputInTransaction(second_tx_id, block_id)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Try to use the transaction input twice with different signatures in one block.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |input = tx1        | |
// | |input = tx1        | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn same_input_diff_sig_in_the_same_tx(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let tx1_output_value = rng.gen_range(100_000..200_000);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, tx1_output_value);

        let input1 = TxInput::new(
            first_tx.get_id().into(),
            0,
            InputWitness::NoSignature(Some(vec![0, 1, 2])),
        );
        let input2 = TxInput::new(
            first_tx.get_id().into(),
            0,
            InputWitness::NoSignature(Some(vec![0, 1, 2, 3])),
        );
        let second_tx = TransactionBuilder::new()
            .add_input(input1)
            .add_input(input2)
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();
        let second_tx_id = second_tx.get_id();

        let block = tf.make_block_builder().with_transactions(vec![first_tx, second_tx]).build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::DuplicateInputInTransaction(second_tx_id, block_id)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Try to use the transaction twice in one block.
//
// +--Block----------------+
// |                       |
// | +-------tx-1--------+ |
// | |input = prev_block | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |                   | |
// | +-------------------+ |
// |                       |
// | +-------tx-2--------+ |
// | |                   | |
// | +-------------------+ |
// +-----------------------+
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn duplicate_tx_in_the_same_block(#[case] seed: Seed) {
    common::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let first_tx = tx_from_genesis(tf.genesis(), &mut rng, 1);

        let second_tx = TransactionBuilder::new().build();
        let second_tx_id = second_tx.get_id();

        let block = tf
            .make_block_builder()
            .with_transactions(vec![first_tx, second_tx.clone(), second_tx])
            .build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::DuplicatedTransactionInBlock(second_tx_id, block_id)
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

// Creates a transaction with an input based on the first transaction from the genesis block.
fn tx_from_genesis(genesis: &Genesis, rng: &mut impl Rng, output_value: u128) -> Transaction {
    TransactionBuilder::new()
        .add_input(TxInput::new(
            OutPointSourceId::BlockReward(genesis.get_id().into()),
            0,
            empty_witness(rng),
        ))
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(output_value)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        ))
        .build()
}

// Creates a transaction with an input based on the specified transaction id.
fn tx_from_tx(tx: &Transaction, output_value: u128) -> Transaction {
    let input = TxInput::new(tx.get_id().into(), 0, InputWitness::NoSignature(None));
    let output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(output_value)),
        OutputPurpose::Transfer(anyonecanspend_address()),
    );
    Transaction::new(0, vec![input], vec![output], 0).unwrap()
}
