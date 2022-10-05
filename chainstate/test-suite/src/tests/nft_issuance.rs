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

use crate::tests::nft_utils::random_creator;
use chainstate::{
    is_rfc1738_valid_symbol, BlockError, ChainstateError, CheckBlockError,
    CheckBlockTransactionsError, TokensError,
};
use chainstate_test_framework::{TestBlockInfo, TestFramework, TransactionBuilder};
use common::chain::tokens::{Metadata, NftIssuanceV1};
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{OutputValue, TokenData},
    Destination, OutputPurpose, TxInput, TxOutput,
};
use rstest::rstest;
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_name_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Name is too long
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(
                                    &mut rng,
                                    max_name_len + 1..max_name_len + 1000,
                                )
                                .into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorInvalidNameLength(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_empty_name(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Name is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: vec![],
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorInvalidNameLength(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_invalid_name(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // try all possible chars for ticker and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() {
                continue;
            }

            let name = gen_text_with_non_ascii(c, &mut rng, max_name_len);

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name,
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: None,
                                    additional_metadata_uri: None,
                                    media_uri: None,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
                            TokensError::IssueErrorNameHasNoneAlphaNumericChar(_, _)
                        )
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_test_ticker_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Ticker is too long
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(
                                    &mut rng,
                                    max_ticker_len + 1..max_ticker_len + 1000,
                                )
                                .into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_empty_ticker(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();

        // Ticker is empty
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: vec![],
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_invalid_ticker(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // try all possible chars for ticker and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() {
                continue;
            }

            let ticker = gen_text_with_non_ascii(c, &mut rng, max_ticker_len);

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker,
                                    icon_uri: None,
                                    additional_metadata_uri: None,
                                    media_uri: None,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_test_description_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Description is too long
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(
                                    &mut rng,
                                    max_desc_len + 1..max_desc_len + 1000,
                                )
                                .into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorInvalidDescriptionLength(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_empty_description(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Description is empty
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: vec![],
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorInvalidDescriptionLength(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_invalid_description(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // try all possible chars for description and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() {
                continue;
            }

            let description = gen_text_with_non_ascii(c, &mut rng, max_desc_len);

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description,
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: None,
                                    additional_metadata_uri: None,
                                    media_uri: None,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
                            TokensError::IssueErrorDescriptionHasNoneAlphaNumericChar(_, _)
                        )
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_icon_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Ticker is too long
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                ),
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorIncorrectIconURI(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_icon_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Ticker is too long
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: Some(vec![]),
                                additional_metadata_uri: None,
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorIncorrectIconURI(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_icon_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        // try all possible chars for description and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc1738_valid_symbol(char::from(c)) {
                continue;
            }

            let icon_uri = Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri,
                                    additional_metadata_uri: None,
                                    media_uri: None,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
                            TokensError::IssueErrorIncorrectIconURI(_, _)
                        )
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_metadata_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Metadata URI is too long
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                ),
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_metadata_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Metadata URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: Some(vec![]),
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_metadata_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        // try all possible chars for description and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric or valid symbol according to rfc1738, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc1738_valid_symbol(char::from(c)) {
                continue;
            }

            let additional_metadata_uri = Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: None,
                                    additional_metadata_uri,
                                    media_uri: None,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_media_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Media URI is too long
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                ),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorIncorrectMediaURI(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_media_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        // Media URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: None,
                                additional_metadata_uri: None,
                                media_uri: Some(vec![]),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
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
                        TokensError::IssueErrorIncorrectMediaURI(_, _)
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_media_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        // try all possible chars for description and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric or valid symbol according to rfc1738, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc1738_valid_symbol(char::from(c)) {
                continue;
            }

            let media_uri = Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: None,
                                    additional_metadata_uri: None,
                                    media_uri,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            })),
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
                            TokensError::IssueErrorIncorrectMediaURI(_, _)
                        )
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_valid_case(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let valid_rfc1738_url =
            b"https://something.com/?a:b.c_d-e~f!g/h?I#J[K]L@M$N&O/P'Q(R)S*T+U,V;W=Xyz".to_vec();

        let output_value = OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: Some(valid_rfc1738_url.clone()),
                additional_metadata_uri: Some(valid_rfc1738_url.clone()),
                media_uri: Some(valid_rfc1738_url.clone()),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }));

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
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

        assert_eq!(
            block_index.block_height(),
            common::primitives::BlockHeight::from(1)
        );

        let block = tf.block(*block_index.block_id());
        let outputs = &TestBlockInfo::from_block(&block).txns[0].1;
        let issuance_output = &outputs[0];

        assert_eq!(issuance_output.value(), &output_value);
    })
}
