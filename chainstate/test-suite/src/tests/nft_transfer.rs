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

use rstest::rstest;

use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{NftIssuance, TokenId},
        ChainstateUpgradeBuilder, Destination, NetUpgrades, OutPointSourceId, TokenIssuanceVersion,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable},
};
use randomness::Rng;
use test_utils::{
    random::{make_seedable_rng, Seed},
    token_utils::random_nft_issuance,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_transfer_wrong_id(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(genesis_outpoint_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        assert!(tf
            .outputs_from_genblock(block.get_id().into())
            .contains_key(&issuance_outpoint_id));

        // Try to transfer NFT with wrong ID
        let random_token_id = TokenId::random_using(&mut rng);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(random_token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(random_token_id)
                    ),
                    tx_id.into()
                )
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(genesis_outpoint_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        assert_eq!(block.transactions()[0], tx);

        // Try to transfer more NFT than we have in input
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen_range(2..123))),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                ))
            )
        );
    })
}

// Transferring zero amount of NFTs is allowed.
// TODO: perhaps we should prohibit it?
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_zero_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let coins_outpoint = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
            0,
        );
        let coins_amount = tf.coin_amount_from_utxo(&coins_outpoint);
        let token_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let tx_first_input = TxInput::Utxo(coins_outpoint.clone());
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((coins_amount - token_issuance_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let issuance_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0);
        let coins_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 1);
        tf.make_block_builder()
            .add_transaction(tx.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        // Create a tx that consumes the NFT in an input and produces a bunch of zero amount outputs
        // and optionally a normal output as well.
        let mut tx_builder = TransactionBuilder::new()
            .add_input(issuance_outpoint.into(), InputWitness::NoSignature(None));
        let zero_outputs_count = rng.gen_range(1..5);
        for _ in 0..zero_outputs_count {
            tx_builder = tx_builder.add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::ZERO),
                Destination::AnyoneCanSpend,
            ));
        }

        if rng.gen_bool(0.5) {
            // Also make the actual transfer
            tx_builder = tx_builder.add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ));
        }

        let tx = tx_builder.build();
        tf.make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        // Special case - transfer zero amount of the NFT when it's not present in the inputs.
        let mut tx_builder = TransactionBuilder::new()
            .add_input(coins_outpoint.into(), InputWitness::NoSignature(None));
        for _ in 0..zero_outputs_count {
            tx_builder = tx_builder.add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::ZERO),
                Destination::AnyoneCanSpend,
            ));
        }

        let tx = tx_builder.build();
        tf.make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_different_nft_than_one_in_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // Issuance a few different NFT
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
        let first_tx_first_input = TxInput::from_utxo(genesis_outpoint_id, 0);
        let first_token_id = TokenId::from_tx_input(&first_tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(first_tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                first_token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_issuance_fee * 2).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let first_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        tf.make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let second_tx_first_input = TxInput::from_utxo(first_issuance_outpoint_id.clone(), 0);
        let second_token_id = TokenId::from_tx_input(&second_tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(second_tx_first_input, InputWitness::NoSignature(None))
            .add_input(
                TxInput::from_utxo(first_issuance_outpoint_id, 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(first_token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::IssueNft(
                second_token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let second_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        tf.make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        // Try to spend 2 NFTs but use one ID

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id.clone(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id, 2),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(first_token_id, Amount::from_atoms(2)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(first_token_id)
                    ),
                    tx_id.into()
                ))
            )
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_valid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(genesis_outpoint_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(tf.chain_config().as_ref(), &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let _ = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        // Valid case
        let transfer_value = OutputValue::TokenV1(token_id, Amount::from_atoms(1));
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        transfer_value.clone(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(block_index.block_height(), BlockHeight::from(2));

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let transfer_output = &outputs[0];

        assert_eq!(get_output_value(transfer_output).unwrap(), transfer_value);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ensure_nft_cannot_be_printed_from_tokens_op(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .token_issuance_version(TokenIssuanceVersion::V1)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let issuance_tx_first_input = TxInput::from_utxo(genesis_outpoint_id, 0);
        let token_id = TokenId::from_tx_input(&issuance_tx_first_input);

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let nft_issuance = random_nft_issuance(tf.chainstate.get_chain_config(), &mut rng);

        // Issue
        let tx = TransactionBuilder::new()
            .add_input(issuance_tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(nft_issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Try print Nfts on transfer
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Transfer
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    })
}
