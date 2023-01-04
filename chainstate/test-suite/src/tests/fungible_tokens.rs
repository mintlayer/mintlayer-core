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

use std::vec;

use chainstate::{
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::tokens::{Metadata, NftIssuance, TokenIssuance, TokenTransfer};
use common::primitives::{id, Id};
use common::{
    chain::{
        signature::inputsig::InputWitness,
        tokens::{token_id, OutputValue, TokenData, TokenId},
        Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::{hash::StreamHasher, random::Rng};
use expect_test::expect;
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Ticker is too long
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenIssuance {
                            token_ticker: random_string(&mut rng, 10..u16::MAX as usize)
                                .as_bytes()
                                .to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
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
                    .add_input(
                        TxInput::new(outpoint_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenIssuance {
                            token_ticker: b"".to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
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

        {
            // try all possible chars for ticker and ensure everything fails except for alphanumeric chars
            for c in u8::MIN..u8::MAX {
                // if c is alphanumeric, then this doesn't produce an error, skip it
                if c.is_ascii_alphanumeric() {
                    continue;
                }

                let token_ticker = gen_text_with_non_ascii(
                    c,
                    &mut rng,
                    tf.chainstate.get_chain_config().token_max_ticker_len(),
                );

                // Ticker contain non alpha-numeric char
                let result = tf
                    .make_block_builder()
                    .add_transaction(
                        TransactionBuilder::new()
                            .add_input(
                                TxInput::new(outpoint_source_id.clone(), 0),
                                InputWitness::NoSignature(None),
                            )
                            .add_output(TxOutput::new(
                                TokenIssuance {
                                    token_ticker,
                                    amount_to_issue: Amount::from_atoms(
                                        rng.gen_range(1..u128::MAX),
                                    ),
                                    number_of_decimals: rng.gen_range(1..18),
                                    metadata_uri: random_string(&mut rng, 1..1024)
                                        .as_bytes()
                                        .to_vec(),
                                }
                                .into(),
                                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                            ))
                            .add_output(TxOutput::new(
                                OutputValue::Coin(token_min_issuance_fee),
                                OutputPurpose::Burn,
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
            }
        }

        // Issue amount is zero
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenIssuance {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(0),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueAmountIsZero(_, _))
                ))
            ))
        ));

        // Too many decimals
        {
            let decimals_count_to_use = tf.chainstate.get_chain_config().token_max_dec_count() + 1;

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            TokenIssuance {
                                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                                amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                                number_of_decimals: decimals_count_to_use,
                                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                            }
                            .into(),
                            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                        ))
                        .add_output(TxOutput::new(
                            OutputValue::Coin(token_min_issuance_fee),
                            OutputPurpose::Burn,
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
        }

        // URI is too long
        {
            let uri_len_range_to_use =
                (tf.chainstate.get_chain_config().token_max_uri_len() + 1)..u16::MAX as usize;

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            TokenIssuance {
                                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                                amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                                number_of_decimals: rng.gen_range(1..18),
                                metadata_uri: random_string(&mut rng, uri_len_range_to_use)
                                    .as_bytes()
                                    .to_vec(),
                            }
                            .into(),
                            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                        ))
                        .add_output(TxOutput::new(
                            OutputValue::Coin(token_min_issuance_fee),
                            OutputPurpose::Burn,
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
        }

        // URI contain non alpha-numeric char
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenIssuance {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                            number_of_decimals: rng.gen_range(1..18),
                            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
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
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(
            block.transactions()[0].transaction().outputs()[0].value(),
            &output_value.into()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_transfer_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
        let genesis_outpoint_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
        };

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();
        assert_eq!(
            block.transactions()[0].transaction().outputs()[0].value(),
            &output_value.clone().into()
        );
        let issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();

        // attempt double-spend
        let result = tf
            .make_block_builder()
            .with_parent((*block_index.block_id()).into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value.into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );

        // Try to transfer exceed amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        })
                        .into(),
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
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id: TokenId::random_using(&mut rng),
                            amount: total_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );

        // Try to transfer zero amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(0),
                        })
                        .into(),
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
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
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
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let genesis_outpoint_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a couple of tokens
        let issuance_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        issuance_value.clone().into(),
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
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(
            block.transactions()[0].transaction().outputs()[0].value(),
            &issuance_value.into()
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_with_insufficient_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let coins_value = (tf.genesis().utxos()[0].value().clone().coin_amount().unwrap()
            - token_min_issuance_fee)
            .unwrap();
        let genesis_outpoint_id = tf.genesis().get_id().into();

        // Issuance data
        let issuance_data = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let block = tf
            .make_block_builder()
            // All coins in inputs added to outputs, fee = 0 coins
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_data.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(coins_value),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(
                            (token_min_issuance_fee - Amount::from_atoms(1)).unwrap(),
                        ),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build();

        let result = tf.process_block(block, BlockSource::Local);

        // Try to process tx with insufficient token fees
        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));

        // Valid issuance
        let genesis_outpoint_id = tf.genesis().get_id().into();
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_data.into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
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
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // Due to transfer a piece of funds, let's limit the start range value
        let total_funds = Amount::from_atoms(rng.gen_range(4..u128::MAX - 1));
        let quarter_funds = (total_funds / 4).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value.into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = block.transactions()[0].transaction().get_id().into();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Split tokens in outputs
        let split_block = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    // One piece of tokens in the first output, other piece of tokens in the second output
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: (total_funds - quarter_funds).unwrap(),
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let split_outpoint_id: OutPointSourceId =
            split_block.transactions()[0].transaction().get_id().into();
        tf.process_block(split_block, BlockSource::Local).unwrap().unwrap();

        // Collect these in one output
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(split_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(split_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
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
fn burn_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // Due to burn a piece of funds, let's limit the start range value
        let total_funds = Amount::from_atoms(rng.gen_range(4..u128::MAX - 1));
        // Round down
        let half_funds = (total_funds / 2).unwrap();
        let quarter_funds = (total_funds / 4).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Try burn more than we have in input
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        }
                        .into(),
                        OutputPurpose::Burn,
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

        // Valid case: Burn 25% with burn data, and burn 25% by not specifying an output, and transfer the remaining 50%
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: half_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let first_burn_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();

        // Valid case: Burn 50% and 50% transfer
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(first_burn_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let second_burn_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();

        // Valid case: Try to burn the rest 50%
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(second_burn_outpoint_id.clone(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let _: OutPointSourceId = block.transactions()[0].transaction().get_id().into();

        // Try to transfer burned tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(second_burn_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_and_try_to_double_spend_tokens(#[case] seed: Seed) {
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
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let issuance_data = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_data,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let issuance_outpoint_id: OutPointSourceId =
            issuance_block.transactions()[0].transaction().get_id().into();
        let token_id = token_id(issuance_block.transactions()[0].transaction()).unwrap();

        // B1 - burn all tokens in mainchain
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
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
        let b1_outpoint_id: OutPointSourceId =
            block_b1.transactions()[0].transaction().get_id().into();

        // Try to transfer burnt tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(b1_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );

        // Let's add C1
        let output_value = OutputValue::Coin(Amount::from_atoms(123453));
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(b1_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
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
        let c1_outpoint_id: OutPointSourceId =
            block_c1.transactions()[0].transaction().get_id().into();
        // Let's add D1
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(c1_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
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
        let _: OutPointSourceId = block_d1.transactions()[0].transaction().get_id().into();

        // Second chain - B2
        let block_b2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let b2_outpoint_id: OutPointSourceId =
            block_b2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_b2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // C2 - burn all tokens in a second chain
        let block_c2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(b2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(b2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let c2_outpoint_id: OutPointSourceId =
            block_c2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_c2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // Now D2 trying to spend tokens from mainchain
        let block_d2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(c2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(c2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build();
        let d2_outpoint_id: OutPointSourceId =
            block_d2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_d2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // Block E2 will cause reorganization
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(d2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(d2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Coin(Amount::from_atoms(123453)),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn attempt_to_print_tokens_one_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // To avoid CoinOrTokenOverflow, random value can't be more than u128::MAX / 2
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX / 2));

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Try to transfer a bunch of outputs where each separately do not exceed input tokens value, but a sum of outputs larger than inputs.
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: (total_funds + Amount::from_atoms(1)).unwrap(),
                        })
                        .into(),
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
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
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
fn attempt_to_print_tokens_two_outputs(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // To avoid CoinOrTokenOverflow, random value can't be more than u128::MAX / 2
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX / 2));

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Try to transfer a bunch of outputs where each separately do not exceed input tokens value, but a sum of outputs larger than inputs.
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
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
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
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
fn spend_different_token_than_one_in_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
        // Issuance a few different tokens
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        output_value,
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin((token_min_issuance_fee * 2).unwrap()),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let first_issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();
        let first_token_id = token_id(block.transactions()[0].transaction()).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(first_issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(first_issuance_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id: first_token_id,
                            amount: total_funds,
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        TokenIssuance {
                            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                            amount_to_issue: total_funds,
                            number_of_decimals: 1,
                            metadata_uri: b"https://some_site.meta".to_vec(),
                        }
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let second_issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();
        let _ = token_id(block.transactions()[0].transaction()).unwrap();

        // Try to spend sum of input tokens

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(second_issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(second_issuance_outpoint_id.clone(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::new(second_issuance_outpoint_id, 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id: first_token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        })
                        .into(),
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
fn tokens_reorgs_and_cleanup_data(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new token
        let issuance_value = TokenIssuance {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let genesis_id = tf.genesis().get_id();
        let genesis_outpoint_id = tf.genesis().get_id().into();
        let block_index = tf
            .make_block_builder()
            .with_parent(genesis_id.into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        issuance_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Coin(token_min_issuance_fee),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let token_id = token_id(issuance_block.transactions()[0].transaction()).unwrap();

        // Check tokens available in storage
        let token_aux_data = tf.chainstate.get_token_aux_data(token_id).unwrap().unwrap();
        // Check id
        assert!(issuance_block.get_id() == token_aux_data.issuance_block_id());
        let issuance_tx = &issuance_block.transactions()[0];
        assert!(issuance_tx.transaction().get_id() == token_aux_data.issuance_tx().get_id());
        // Check issuance storage in the chain and in the storage
        assert_eq!(
            issuance_tx.transaction().outputs()[0].value(),
            &issuance_value.clone().into()
        );
        assert_eq!(
            token_aux_data.issuance_tx().outputs()[0].value(),
            &issuance_value.into()
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
                issuance_tx.transaction().get_id()
            ))
            .unwrap()
            .is_none());

        // Check that tokens not in storage
        assert!(tf
            .chainstate
            .get_token_id_from_issuance_tx(&issuance_tx.transaction().get_id())
            .unwrap()
            .is_none());

        assert!(tf.chainstate.get_token_info_for_rpc(token_id).unwrap().is_none());

        assert!(tf.chainstate.get_token_aux_data(token_id).unwrap().is_none());
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_in_block_reward(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let (_, pub_key) =
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::RistrettoSchnorr);

        // Check if it issuance
        let reward_output = TxOutput::new(
            TokenIssuance {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                amount_to_issue: total_funds,
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            }
            .into(),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key.clone())),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it transfer
        let reward_output = TxOutput::new(
            TokenData::TokenTransfer(TokenTransfer {
                token_id: TokenId::random_using(&mut rng),
                amount: total_funds,
            })
            .into(),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it burn
        let reward_output = TxOutput::new(
            TokenTransfer {
                token_id: TokenId::random_using(&mut rng),
                amount: total_funds,
            }
            .into(),
            OutputPurpose::Burn,
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
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
fn chosen_hashes_for_token_data() {
    // If fields order of TokenData accidentally will be changed, snapshots cause fail
    let mut hash_stream = id::DefaultHashAlgoStream::new();

    // Token issuance
    let token_issuance = TokenIssuance {
        token_ticker: b"SOME".to_vec(),
        amount_to_issue: Amount::from_atoms(123456789),
        number_of_decimals: 123,
        metadata_uri: "https://some_site.some".as_bytes().to_vec(),
    };
    id::hash_encoded_to(&token_issuance, &mut hash_stream);
    expect![[r#"
            0xa63a4ae4146ff43096baa2b8e648edca108abf34960e746def28443957ffe04e
        "#]]
    .assert_debug_eq(&Id::<TokenIssuance>::new(hash_stream.finalize().into()).get());

    // NFT issuance
    let nft_issuance = NftIssuance {
        metadata: Metadata {
            creator: None,
            name: b"SOME".to_vec(),
            description: b"NFT".to_vec(),
            ticker: b"Ticker".to_vec(),
            icon_uri: DataOrNoVec::from(Some(vec![9, 8, 7, 6, 5, 4, 3, 2, 1])),
            additional_metadata_uri: DataOrNoVec::from(Some(vec![
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ])),
            media_uri: DataOrNoVec::from(Some(vec![20, 21, 22, 23, 24, 25, 26, 27, 28, 29])),
            media_hash: vec![30, 31, 32, 33, 34, 35, 36, 37, 38, 39],
        },
    };
    id::hash_encoded_to(&nft_issuance, &mut hash_stream);
    expect![[r#"
            0xbe6ad7ed36c9f898fae21bf5f3164c090c979a5b4083643a60276028012db15a
        "#]]
    .assert_debug_eq(&Id::<NftIssuance>::new(hash_stream.finalize().into()).get());

    // Token Transfer
    let token_data = TokenData::TokenTransfer(TokenTransfer {
        token_id: TokenId::zero(),
        amount: Amount::from_atoms(1234567890),
    });
    id::hash_encoded_to(&token_data, &mut hash_stream);
    expect![[r#"
            0x988fb6c034fd307d609c24c2b9534c7bf370c198bf5229f83343d22669e84d4f
        "#]]
    .assert_debug_eq(&Id::<TokenData>::new(hash_stream.finalize().into()).get());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_transfer_in_the_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenIssuance {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(100_000..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(token_min_issuance_fee),
                OutputPurpose::Burn,
            ))
            .build();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id: token_id(tx_1.transaction()).unwrap(),
                    amount: Amount::from_atoms(rng.gen_range(1..100_000)),
                })
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .build_and_process()
            .unwrap()
            .unwrap();
    })
}
