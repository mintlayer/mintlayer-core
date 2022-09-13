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

use chainstate::{BlockError, BlockSource, ChainstateError};
use chainstate::{CheckBlockError, CheckBlockTransactionsError, ConnectTransactionError};
use chainstate_test_framework::{TestBlockInfo, TestFramework, TransactionBuilder};
use common::chain::tokens::TokensError;
use common::primitives::{id, Id};
use common::{
    chain::{
        signature::inputsig::InputWitness,
        tokens::{token_id, OutputValue, TokenData, TokenId},
        Destination, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::random::distributions::uniform::SampleRange;
use crypto::{hash::StreamHasher, random::Rng};
use expect_test::expect;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

fn random_string<R: SampleRange<usize>>(rng: &mut impl Rng, range_len: R) -> String {
    use crypto::random::distributions::{Alphanumeric, DistString};
    if range_len.is_empty() {
        return String::new();
    }
    let len = rng.gen_range(range_len);
    Alphanumeric.sample_string(rng, len)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Ticker is too long
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 10..u16::MAX as usize)
                                .as_bytes()
                                .to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorInvalidTickerLength(_, _)
                    )
                ))
            ))
        ));

        // Ticker doesn't exist
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: b"".to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorInvalidTickerLength(_, _)
                    )
                ))
            ))
        ));

        // Ticker contain non alpha-numeric char
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: "💖".as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorTickerHasNoneAlphaNumericChar(_, _)
                    )
                ))
            ))
        ));

        // Issue amount is too low
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(0),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorIncorrectAmount(_, _)
                    )
                ))
            ))
        ));

        // Too many decimals
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: 123,
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorTooManyDecimals(_, _)
                    )
                ))
            ))
        ));

        // URI is too long
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1025..u16::MAX as usize)
                                .as_bytes()
                                .to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorIncorrectMetadataURI(_, _)
                    )
                ))
            ))
        ));

        // URI contain non alpha-numeric char
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::IssueErrorIncorrectMetadataURI(_, _)
                    )
                ))
            ))
        ));

        // Valid case
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        outpoint_source_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_transfer_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        // Issue a new token
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
        });

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(&block.transactions()[0]).unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer exceed amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));

        // Try to transfer token with wrong id
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id: TokenId::random(),
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::MissingOutputOrSpent)
            ))
        ));

        // Try to transfer zero amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(0),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::TransferZeroTokens(_, _))
                ))
            ))
        ));

        // Valid case - Transfer tokens
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn multiple_token_issuance_in_one_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        // Issue a couple of tokens
        let issuance_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        issuance_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        issuance_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(
                        TokensError::MultipleTokenIssuanceInTransaction(_, _)
                    )
                ))
            ))
        ));

        // Valid issuance
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_with_insufficient_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let genesis_info = TestBlockInfo::from_genesis(&tf.genesis());
        let coins_value = genesis_info.txns[0].1[0].value().clone();
        assert!(matches!(coins_value, OutputValue::Coin(_)));
        let genesis_outpoint_id = genesis_info.txns[0].0.clone();

        // Issuance
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block = tf
            .make_block_builder()
            // All coins in inputs added to outputs, fee = 0 coins
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        coins_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();

        let result = tf.process_block(block, BlockSource::Local);

        // Try to process tx with insufficient token fees
        assert!(matches!(
            dbg!(result),
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));

        // Valid issuance
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn transfer_split_and_combine_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // Due to transfer a piece of funds, let's limit the start range value
        let total_funds = Amount::from_atoms(rng.gen_range(4..u128::MAX - 1));
        let quarter_funds = (total_funds / 4).unwrap();

        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let token_id = token_id(&block.transactions()[0]).unwrap();

        // Split tokens in outputs
        let split_block = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    // One piece of tokens in the first output, other piece of tokens in the second output
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: (total_funds - quarter_funds).unwrap(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: quarter_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let split_outpoint_id = TestBlockInfo::from_block(&split_block).txns[0].0.clone();
        tf.process_block(split_block, BlockSource::Local).unwrap().unwrap();

        // Collect these in one output
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        split_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        split_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_burn_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // Due to burn a piece of funds, let's limit the start range value
        let total_funds = Amount::from_atoms(rng.gen_range(4..u128::MAX - 1));
        // Round down
        let half_funds = (total_funds / 2).unwrap();
        let quarter_funds = (total_funds / 4).unwrap();

        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let token_id = token_id(&block.transactions()[0]).unwrap();

        // Try burn more than we have in input
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: Amount::from_atoms(total_funds.into_atoms() + 1),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));

        // Valid case: Burn 25% through burn data, and burn 25% with just don't add output for them, and transfer the rest 50%
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: quarter_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: half_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let first_burn_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Valid case: Burn 50% and 50% transfer
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        first_burn_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: quarter_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: quarter_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let second_burn_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Valid case: Try to burn the rest 50%
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        second_burn_outpoint_id.clone(),
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: quarter_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let _ = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer burned tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        second_burn_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::AttemptToTransferBurnedTokens
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_reorg_and_try_to_double_spend_tokens(#[case] seed: Seed) {
    //     B1 - C1 - D1
    //   /
    // A
    //   \
    //     B2 - C2
    //
    // Where in A, we issue a token, and it becomes part of the utxo-set.
    // Now assuming chain-trust per block is 1, it's obvious that D1 represents the tip.
    // Consider a case where B1 spends the issued token output. If a Block D2 was added
    // to this chain (whose previous block is C2), and D2 contains an input that also spends
    // B1, check that output is spent.

    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&issuance_block).txns[0].0.clone();
        let token_id = token_id(&issuance_block.transactions()[0]).unwrap();

        // B1 - burn all tokens in mainchain
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_b1 = tf.block(*block_index.block_id());
        let b1_outpoint_id = TestBlockInfo::from_block(&block_b1).txns[0].0.clone();

        // Try to transfer spent tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        b1_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::AttemptToTransferBurnedTokens
                ))
            ))
        ));

        // Let's add C1
        let output_value = OutputValue::Coin(Amount::from_atoms(123453));
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        b1_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_c1 = tf.block(*block_index.block_id());
        let c1_outpoint_id = TestBlockInfo::from_block(&block_c1).txns[0].0.clone();
        // Let's add D1
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        c1_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_d1 = tf.block(*block_index.block_id());
        let _ = TestBlockInfo::from_block(&block_d1).txns[0].0.clone();

        // Second chain - B2
        let block_b2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let b2_outpoint_id = TestBlockInfo::from_block(&block_b2).txns[0].0.clone();
        assert!(
            tf.process_block(block_b2, BlockSource::Local).unwrap().is_none(),
            "Reog is not allowed at this height"
        );

        // C2 - burn all tokens in a second chain
        let block_c2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        b2_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        b2_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let c2_outpoint_id = TestBlockInfo::from_block(&block_c2).txns[0].0.clone();
        assert!(
            tf.process_block(block_c2, BlockSource::Local).unwrap().is_none(),
            "Reog is not allowed at this height"
        );

        // Now D2 trying to spend tokens from mainchain
        let block_d2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        c2_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        c2_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1 {
                            token_id,
                            amount_to_burn: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let d2_outpoint_id = TestBlockInfo::from_block(&block_d2).txns[0].0.clone();
        assert!(
            tf.process_block(block_d2, BlockSource::Local).unwrap().is_none(),
            "Reog is not allowed at this height"
        );

        // Block E2 will cause reorganization
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        d2_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        d2_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123453)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::MissingOutputOrSpent)
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_attempt_to_print_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // To avoid CoinOrTokenOverflow, random value can't be more than u128::MAX / 2
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX / 2));

        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let token_id = token_id(&block.transactions()[0]).unwrap();

        // Try to transfer a bunch of outputs where each separately do not exceed input tokens value, but a sum of outputs larger than inputs.
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));

        // Valid case - try to transfer correct amount of tokens
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_attempt_to_mix_input_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
        // Issuance a few different tokens
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin((token_min_issuance_fee * 2).unwrap()),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let first_issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let first_token_id = token_id(&block.transactions()[0]).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        first_issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        first_issuance_outpoint_id,
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id: first_token_id,
                            amount: total_funds,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: total_funds,
                            number_of_decimals: 1,
                            metadata_uri: b"https://some_site.meta".to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let second_issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let _ = token_id(&block.transactions()[0]).unwrap();

        // Try to spend sum of input tokens

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        second_issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        second_issuance_outpoint_id.clone(),
                        1,
                        InputWitness::NoSignature(None),
                    ))
                    .add_input(TxInput::new(
                        second_issuance_outpoint_id,
                        2,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id: first_token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin((token_min_issuance_fee * 2).unwrap()),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_tokens_reorgs_and_cleanup_data(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        // Issue a new token
        let issuance_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        });
        let genesis_id = tf.genesis().get_id();
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let block_index = tf
            .make_block_builder()
            .with_parent(genesis_id.into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        issuance_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let token_id = token_id(&issuance_block.transactions()[0]).unwrap();

        // Check tokens available in storage
        let token_aux_data = tf.chainstate.get_token_aux_data(token_id).unwrap().unwrap();
        // Check id
        assert!(issuance_block.get_id() == token_aux_data.issuance_block_id());
        let issuance_tx = &issuance_block.transactions()[0];
        assert!(issuance_tx.get_id() == token_aux_data.issuance_tx().get_id());
        // Check issuance storage in the chain and in the storage
        assert_eq!(issuance_tx.outputs()[0].value(), &issuance_value);
        assert_eq!(
            token_aux_data.issuance_tx().outputs()[0].value(),
            &issuance_value
        );

        // Cause reorg
        tf.create_chain(&tf.genesis().get_id().into(), 5, &mut rng).unwrap();

        // Check that reorg happened
        let height = block_index.block_height();
        assert!(
            tf.chainstate.get_block_id_from_height(&height).unwrap().map_or(false, |id| &id
                .classify(&tf.chainstate.get_chain_config())
                .chain_block_id()
                .unwrap()
                != block_index.block_id())
        );

        // Check that issuance transaction in the storage is removed
        assert!(tf
            .chainstate
            .get_mainchain_tx_index(&common::chain::OutPointSourceId::Transaction(
                issuance_tx.get_id()
            ))
            .unwrap()
            .is_none());

        // Check that tokens not in storage
        assert!(tf
            .chainstate
            .get_token_id_from_issuance_tx(&issuance_tx.get_id())
            .unwrap()
            .is_none());

        assert!(tf.chainstate.get_token_info_for_rpc(token_id).unwrap().is_none());

        assert!(matches!(
            tf.chainstate.get_token_aux_data(token_id),
            Err(ChainstateError::FailedToReadProperty(
                chainstate_types::PropertyQueryError::TokensError(
                    TokensError::TokensNotRegistered(_)
                )
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_tokens_issuance_in_block_reward(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let (_, pub_key) = crypto::key::PrivateKey::new(crypto::key::KeyKind::RistrettoSchnorr);

        // Check if it issuance
        let reward_output = TxOutput::new(
            OutputValue::Token(TokenData::TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                amount_to_issue: total_funds,
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            }),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key.clone())),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it transfer
        let reward_output = TxOutput::new(
            OutputValue::Token(TokenData::TokenTransferV1 {
                token_id: TokenId::random(),
                amount: total_funds,
            }),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key.clone())),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it burn
        let reward_output = TxOutput::new(
            OutputValue::Token(TokenData::TokenBurnV1 {
                token_id: TokenId::random(),
                amount_to_burn: total_funds,
            }),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));
    })
}

#[test]
fn snapshot_testing_tokens_data() {
    // If fields order of TokenData accidentally will be changed, snapshots cause fail
    let mut hash_stream = id::DefaultHashAlgoStream::new();

    // Token issuance
    let token_data = TokenData::TokenIssuanceV1 {
        token_ticker: b"SOME".to_vec(),
        amount_to_issue: Amount::from_atoms(123456789),
        number_of_decimals: 123,
        metadata_uri: "https://some_site.some".as_bytes().to_vec(),
    };
    id::hash_encoded_to(&token_data, &mut hash_stream);
    expect![[r#"
            0x7b0482a8a4ebe22005777f6380a8a10432758146c60e7f8b61a768d9152de3f0
        "#]]
    .assert_debug_eq(&Id::<TokenData>::new(hash_stream.finalize().into()).get());

    // Token burn
    let token_data = TokenData::TokenBurnV1 {
        token_id: TokenId::zero(),
        amount_to_burn: Amount::from_atoms(1234567890),
    };
    id::hash_encoded_to(&token_data, &mut hash_stream);
    expect![[r#"
            0xf33c5e6a8bc8575ee5f5f747f2fdb1f7c77f6dc17e7bca5b13f500f672f68b3c
        "#]]
    .assert_debug_eq(&Id::<TokenData>::new(hash_stream.finalize().into()).get());

    // Token Transfer
    let token_data = TokenData::TokenTransferV1 {
        token_id: TokenId::zero(),
        amount: Amount::from_atoms(1234567890),
    };
    id::hash_encoded_to(&token_data, &mut hash_stream);
    expect![[r#"
            0x988fb6c034fd307d609c24c2b9534c7bf370c198bf5229f83343d22669e84d4f
        "#]]
    .assert_debug_eq(&Id::<TokenData>::new(hash_stream.finalize().into()).get());
}
