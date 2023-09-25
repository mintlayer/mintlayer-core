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

use chainstate::{
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::tokens::{TokenIssuanceV1, TokenIssuanceVersioned, TokenTotalSupply};
use common::{
    chain::{
        output_value::OutputValue, signature::inputsig::InputWitness, Destination,
        OutPointSourceId, TxInput, TxOutput,
    },
    primitives::Idable,
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string,
};
use tx_verifier::error::TokenIssuanceError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let token_max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let token_max_dec_count = tf.chainstate.get_chain_config().token_max_dec_count();
        let token_max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        let mut process_block_with_issuance = |issuance: TokenIssuanceVersioned| {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(outpoint_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Tokens(common::chain::TokenOutput::TokenIssuance(
                    Box::new(issuance),
                )))
                .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                .build();
            let tx_id = tx.transaction().get_id();
            let block = tf.make_block_builder().add_transaction(tx).build();
            let block_id = block.get_id();
            let result = tf.process_block(block, BlockSource::Local);
            (result, tx_id, block_id)
        };

        // Ticker is too long
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 10..u16::MAX as usize).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        // Ticker doesn't exist
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        {
            // try all possible chars for ticker and ensure everything fails except for alphanumeric chars
            for c in u8::MIN..u8::MAX {
                // if c is alphanumeric, then this doesn't produce an error, skip it
                if c.is_ascii_alphanumeric() {
                    continue;
                }

                let token_ticker = gen_text_with_non_ascii(c, &mut rng, token_max_ticker_len);

                // Ticker contain non alpha-numeric char
                let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                    token_ticker,
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                    supply_limit: TokenTotalSupply::Unlimited,
                    reissuance_controller: Destination::AnyoneCanSpend,
                });
                let (result, tx_id, block_id) = process_block_with_issuance(issuance);

                assert_eq!(
                    result,
                    Err(ChainstateError::ProcessBlockError(
                        BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                            CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                                tx_id,
                                block_id
                            ))
                        ))
                    ))
                );
            }
        }

        // Too many decimals
        {
            let decimals_count_to_use = token_max_dec_count + 1;

            let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: decimals_count_to_use,
                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                supply_limit: TokenTotalSupply::Unlimited,
                reissuance_controller: Destination::AnyoneCanSpend,
            });
            let (result, tx_id, block_id) = process_block_with_issuance(issuance);
            assert_eq!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorTooManyDecimals,
                            tx_id,
                            block_id
                        ))
                    ))
                ))
            );
        }

        // URI is too long
        {
            let uri_len_range_to_use = (token_max_uri_len + 1)..u16::MAX as usize;

            let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_string(&mut rng, uri_len_range_to_use).as_bytes().to_vec(),
                supply_limit: TokenTotalSupply::Unlimited,
                reissuance_controller: Destination::AnyoneCanSpend,
            });
            let (result, tx_id, block_id) = process_block_with_issuance(issuance);
            assert_eq!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                            tx_id,
                            block_id
                        ))
                    ))
                ))
            );
        }

        // URI contain non alpha-numeric char
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        // Valid case
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(common::chain::TokenOutput::TokenIssuance(
                        Box::new(issuance.clone()),
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        // FIXME: check that token account was created
    });
}

// FIXME: more tests
// FIXME: token_reissuance_with_insufficient_fee
