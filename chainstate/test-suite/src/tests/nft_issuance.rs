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
    is_rfc3986_valid_symbol, BlockError, ChainstateError, CheckBlockError,
    CheckBlockTransactionsError, TokensError,
};
use chainstate_test_framework::{TestBlockInfo, TestFramework, TransactionBuilder};
use common::chain::tokens::OutputValue;
use common::chain::tokens::TokenData;
use common::chain::Block;
use common::chain::OutPointSourceId;
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{Metadata, NftIssuanceV1},
    Destination, OutputPurpose, TxInput, TxOutput,
};
use common::primitives::Idable;
use crypto::random::Rng;
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
fn nft_issuance_name_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

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
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(
                                    &mut rng,
                                    max_name_len + 1..max_name_len + 1000,
                                )
                                .into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: vec![],
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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

        // try all possible chars for name and ensure everything fails except for alphanumeric chars
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
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name,
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(
                                    &mut rng,
                                    max_ticker_len + 1..max_ticker_len + 1000,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: vec![],
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker,
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(
                                    &mut rng,
                                    max_desc_len + 1..max_desc_len + 1000,
                                )
                                .into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: vec![],
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description,
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                )),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let output_value: OutputValue = TokenData::from(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(Some(vec![])),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        })
        .into();
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

        // try all possible chars for icon_uri and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc3986_valid_symbol(char::from(c)) {
                continue;
            }

            let icon_uri =
                DataOrNoVec::from(Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len)));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri,
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                )),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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
        let output_value: OutputValue = TokenData::from(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(Some(vec![])),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        })
        .into();
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

        // try all possible chars for additional_metadata_uri and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric or valid symbol according to rfc1738, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc3986_valid_symbol(char::from(c)) {
                continue;
            }

            let additional_metadata_uri =
                DataOrNoVec::from(Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len)));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri,
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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
                        NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(Some(
                                    random_string(&mut rng, max_uri_len + 1..max_uri_len + 1000)
                                        .into_bytes(),
                                )),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
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
        let output_value: OutputValue = TokenData::from(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(Some(vec![])),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        })
        .into();

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

        // try all possible chars for media_uri and ensure everything fails except for alphanumeric chars
        for c in u8::MIN..u8::MAX {
            // if c is alphanumeric or valid symbol according to rfc1738, then this doesn't produce an error, skip it
            if c.is_ascii_alphanumeric() || is_rfc3986_valid_symbol(char::from(c)) {
                continue;
            }

            let media_uri =
                DataOrNoVec::from(Some(gen_text_with_non_ascii(c, &mut rng, max_uri_len)));

            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::new(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::new(
                            NftIssuanceV1 {
                                metadata: Metadata {
                                    creator: random_creator(),
                                    name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                                    description: random_string(&mut rng, 1..max_desc_len)
                                        .into_bytes(),
                                    ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
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
                        CheckBlockTransactionsError::TokensError(
                            TokensError::IssueErrorIncorrectMediaURI(_, _)
                        )
                    ))
                ))
            ));
        }
    })
}

fn new_block_with_hash(
    rng: &mut impl Rng,
    tf: &mut TestFramework,
    input_source_id: &OutPointSourceId,
    media_hash: Vec<u8>,
) -> Block {
    let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
    let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
    let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
    let name = random_string(rng, 1..max_name_len).into_bytes();
    let description = random_string(rng, 1..max_desc_len).into_bytes();
    let ticker = random_string(rng, 1..max_ticker_len).into_bytes();
    let genesis_id = tf.genesis().get_id();
    tf.make_block_builder()
        .with_parent(genesis_id.into())
        .add_transaction(
            TransactionBuilder::new()
                .add_input(
                    TxInput::new(input_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::new(
                    NftIssuanceV1 {
                        metadata: Metadata {
                            creator: random_creator(),
                            name,
                            description,
                            ticker,
                            icon_uri: DataOrNoVec::from(None),
                            additional_metadata_uri: DataOrNoVec::from(None),
                            media_uri: DataOrNoVec::from(None),
                            media_hash,
                        },
                    }
                    .into(),
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ))
                .build(),
        )
        .build()
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_issuance_check_hash(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let outpoint_source_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let mut rng = make_seedable_rng(seed);

        let min_hash_len = tf.chainstate.get_chain_config().min_hash_len();
        let max_hash_len = tf.chainstate.get_chain_config().max_hash_len();

        // Check too short hash
        for i in 0..min_hash_len {
            let media_hash = vec![rng.gen::<u8>()].repeat(i);

            let block = new_block_with_hash(&mut rng, &mut tf, &outpoint_source_id, media_hash);
            let result = tf.process_block(block, chainstate::BlockSource::Local);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::MediaHashTooShort)
                    ))
                ))
            ));
        }

        // Check too long hash
        for i in (max_hash_len + 1)..=(u8::MAX as usize) {
            let media_hash = vec![rng.gen::<u8>()].repeat(i);

            let block = new_block_with_hash(&mut rng, &mut tf, &outpoint_source_id, media_hash);
            let result = tf.process_block(block, chainstate::BlockSource::Local);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::MediaHashTooLong)
                    ))
                ))
            ));
        }

        // Valid cases
        for hash_size in [
            min_hash_len,
            min_hash_len + 4,
            min_hash_len + 8,
            min_hash_len + 12,
            min_hash_len + 16,
            min_hash_len + 20,
            max_hash_len,
        ] {
            let media_hash = vec![rng.gen::<u8>()].repeat(hash_size);

            let block =
                new_block_with_hash(&mut rng, &mut tf, &outpoint_source_id, media_hash.clone());
            let block_id = block.get_id();
            let _ = tf.process_block(block, chainstate::BlockSource::Local).unwrap();

            let block = tf.block(block_id);
            let outputs = &TestBlockInfo::from_block(&block).txns[0].1;
            let issuance_output = &outputs[0];

            match issuance_output.value().token_data().unwrap() {
                TokenData::NftIssuanceV1(nft) => {
                    assert_eq!(nft.metadata.media_hash(), &media_hash);
                }
                _ => panic!("NFT issuance not found"),
            }
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
        let valid_rfc3986_uri =
            b"https://something.com/?a:b.c_d-e~f!g/h?I#J[K]L@M$N&O/P'Q(R)S*T+U,V;W=Xyz".to_vec();

        let output_value = NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(Some(valid_rfc3986_uri.clone())),
                additional_metadata_uri: DataOrNoVec::from(Some(valid_rfc3986_uri.clone())),
                media_uri: DataOrNoVec::from(Some(valid_rfc3986_uri)),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
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

        assert_eq!(issuance_output.value(), &output_value.into());
    })
}
