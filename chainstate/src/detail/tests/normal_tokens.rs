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

use crate::detail::tests::test_framework::{TestFramework, TransactionBuilder};
use crate::detail::transaction_verifier::error::ConnectTransactionError;
use crate::detail::CheckBlockTransactionsError;
use crate::{
    detail::{tests::TestBlockInfo, CheckBlockError, TokensError},
    BlockError, BlockSource,
};
use common::{
    chain::{
        config::TOKEN_MIN_ISSUANCE_FEE,
        signature::inputsig::InputWitness,
        tokens::{token_id, OutputValue, TokenData, TokenId},
        Destination, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[test]
fn token_issue_test() {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();

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
                            token_ticker: b"TRY TO USE THE LONG NAME".to_vec(),
                            amount_to_issue: Amount::from_atoms(52292852472),
                            number_of_decimals: 1,
                            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorInvalidTickerLength(_, _)
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
                            amount_to_issue: Amount::from_atoms(52292852472),
                            number_of_decimals: 1,
                            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorInvalidTickerLength(_, _)
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
                            amount_to_issue: Amount::from_atoms(52292852472),
                            number_of_decimals: 1,
                            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorTickerHasNoneAlphaNumericChar(_, _)
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
                            token_ticker: "SOME".as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(0),
                            number_of_decimals: 1,
                            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorIncorrectAmount(_, _)
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
                            token_ticker: "SOME".as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(123456789),
                            number_of_decimals: 123,
                            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorTooManyDecimals(_, _)
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
                            token_ticker: b"SOME".to_vec(),
                            amount_to_issue: Amount::from_atoms(52292852472),
                            number_of_decimals: 1,
                            metadata_uri: "https://some_site.meta".repeat(1024).as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorIncorrectMetadataURI(_, _)
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
                            token_ticker: "SOME".as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(52292852472),
                            number_of_decimals: 1,
                            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueErrorIncorrectMetadataURI(_, _)
                ))
            ))
        ));

        // Valid case
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: "SOME".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
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

#[test]
fn token_transfer_test() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();

        // Issue a new token
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: Amount::from_atoms(52_292_852_472),
            number_of_decimals: 1,
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
                            amount: Amount::from_atoms(987_654_321_123),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(_, _)
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
                            amount: Amount::from_atoms(123456789),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
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
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::TransferZeroTokens(_, _)
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
                            amount: Amount::from_atoms(123456789),
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

#[test]
fn multiple_token_issuance_in_one_tx() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();

        // Issue a couple of tokens
        let issuance_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
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
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::MultipleTokenIssuanceInTransaction(_, _)
                ))
            ))
        ));

        // Valid issuance
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
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

        // Issuance
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
        });
        let result = tf
            .make_block_builder()
            // All coins in inputs added to outputs, fee = 0 coins
            .add_test_transaction(&mut rng)
            .add_transaction(
                TransactionBuilder::new()
                    .add_output(TxOutput::new(
                        output_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        // Try to process tx with insufficient token fees
        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::InsufficientTokenFees(_, _))
            ))
        ));

        // Valid issuance
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
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

#[test]
fn transfer_split_and_combine_tokens() {
    utils::concurrency::model(|| {
        const TOTAL_TOKEN_VALUE: Amount = Amount::from_atoms(52292852472);
        let mut tf = TestFramework::default();

        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: TOTAL_TOKEN_VALUE,
            number_of_decimals: 1,
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
                            amount: (TOTAL_TOKEN_VALUE - Amount::from_atoms(123456)).unwrap(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(123456),
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
                            amount: TOTAL_TOKEN_VALUE,
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

#[test]
fn test_burn_tokens() {
    utils::concurrency::model(|| {
        const ISSUED_FUNDS: Amount = Amount::from_atoms(123456788);
        const HALF_ISSUED_FUNDS: Amount = Amount::from_atoms(61728394);
        const QUARTER_ISSUED_FUNDS: Amount = Amount::from_atoms(30864197);

        let mut tf = TestFramework::default();
        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: ISSUED_FUNDS,
            number_of_decimals: 1,
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
                            amount_to_burn: (ISSUED_FUNDS * 2).unwrap(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(_, _)
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
                            amount_to_burn: QUARTER_ISSUED_FUNDS,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: HALF_ISSUED_FUNDS,
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
                            amount_to_burn: QUARTER_ISSUED_FUNDS,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: QUARTER_ISSUED_FUNDS,
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
                            amount_to_burn: QUARTER_ISSUED_FUNDS,
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
                            amount: Amount::from_atoms(123456789),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::AttemptToTransferBurnedTokens)
            ))
        ));
    })
}

#[test]
fn test_reorg_and_try_to_double_spend_tokens() {
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

    utils::concurrency::model(|| {
        const ISSUED_FUNDS: Amount = Amount::from_atoms(1_000_000);

        let mut tf = TestFramework::default();
        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: ISSUED_FUNDS,
            number_of_decimals: 1,
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
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(TOKEN_MIN_ISSUANCE_FEE),
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
                            amount_to_burn: ISSUED_FUNDS,
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
                            amount: ISSUED_FUNDS,
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
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::AttemptToTransferBurnedTokens)
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
                            amount: ISSUED_FUNDS,
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
                            amount_to_burn: ISSUED_FUNDS,
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
                            amount_to_burn: ISSUED_FUNDS,
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
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        ));
    })
}

#[test]
fn test_attempt_to_print_tokens() {
    utils::concurrency::model(|| {
        const ISSUED_FUNDS: Amount = Amount::from_atoms(987_654_321);
        let mut tf = TestFramework::default();

        // Issue a new token
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"SOME".to_vec(),
            amount_to_issue: ISSUED_FUNDS,
            number_of_decimals: 1,
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
                            amount: ISSUED_FUNDS,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1 {
                            token_id,
                            amount: ISSUED_FUNDS,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(_, _)
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
                            amount: ISSUED_FUNDS,
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

#[test]
fn test_attempt_to_mix_input_tokens() {
    utils::concurrency::model(|| {
        const ISSUED_FUNDS: Amount = Amount::from_atoms(987_654_321);
        let mut tf = TestFramework::default();
        // Issuance a few different tokens
        let genesis_outpoint_id = TestBlockInfo::from_genesis(tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::TokenIssuanceV1 {
            token_ticker: b"FIRST".to_vec(),
            amount_to_issue: ISSUED_FUNDS,
            number_of_decimals: 1,
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
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin((TOKEN_MIN_ISSUANCE_FEE * 2).unwrap()),
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
                            amount: ISSUED_FUNDS,
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenIssuanceV1 {
                            token_ticker: b"SECND".to_vec(),
                            amount_to_issue: ISSUED_FUNDS,
                            number_of_decimals: 1,
                            metadata_uri: b"https://some_site.meta".to_vec(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(TOKEN_MIN_ISSUANCE_FEE),
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
                            amount: (ISSUED_FUNDS * 2).unwrap(),
                        }),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin((TOKEN_MIN_ISSUANCE_FEE * 2).unwrap()),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(_, _)
            ))
        ));
    })
}

#[test]
fn test_tokens_storage() {
    utils::concurrency::model(|| {
        // TODO: Test tokens records in the storage before and after token issuance, also after reorg
    })
}

#[test]
fn snapshot_testing_tokens_data() {
    utils::concurrency::model(|| {
        // TODO: Add tests, that will prevent change fields order
    })
}

//TODO: Due to much change in Test Framework, this file should be updated according to new features like TxBuilder
