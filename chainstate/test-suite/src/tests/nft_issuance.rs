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
    is_rfc3986_valid_symbol, BlockError, ChainstateError, CheckBlockError,
    CheckBlockTransactionsError, ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::chain::output_value::OutputValue;
use common::chain::Block;
use common::chain::OutPointSourceId;
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{
        make_token_id, Metadata, NftIssuance, NftIssuanceV0, TokenData, TokenIssuanceVersion,
    },
    ChainstateUpgrade, Destination, TxInput, TxOutput,
};
use common::primitives::{BlockHeight, Idable};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    gen_text_with_non_ascii,
    nft_utils::{random_creator, random_nft_issuance},
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::error::TokenIssuanceError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_name_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    max_name_len + 1..max_name_len + 1000,
                                )
                                .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidNameLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_empty_name(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: vec![],
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidNameLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_name(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name,
                                    description: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_desc_len,
                                    )
                                    .into_bytes(),
                                    ticker: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_ticker_len,
                                    )
                                    .into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorNameHasNoneAlphaNumericChar,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_ticker_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
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
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_empty_ticker(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: vec![],
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_ticker(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
                                    .into_bytes(),
                                    description: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_desc_len,
                                    )
                                    .into_bytes(),
                                    ticker,
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_description_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    max_desc_len + 1..max_desc_len + 1000,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidDescriptionLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_empty_description(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: vec![],
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidDescriptionLength,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_description(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
                                    .into_bytes(),
                                    description,
                                    ticker: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_ticker_len,
                                    )
                                    .into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorDescriptionHasNoneAlphaNumericChar,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_icon_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(Some(
                                    random_ascii_alphanumeric_string(
                                        &mut rng,
                                        max_uri_len + 1..max_uri_len + 1000,
                                    )
                                    .into_bytes(),
                                )),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorIncorrectIconURI,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_icon_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let output_value: OutputValue = TokenData::from(NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
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
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let issuance_output = &outputs[0];

        assert_eq!(get_output_value(issuance_output).unwrap(), output_value);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_icon_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
                                    .into_bytes(),
                                    description: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_desc_len,
                                    )
                                    .into_bytes(),
                                    ticker: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_ticker_len,
                                    )
                                    .into_bytes(),
                                    icon_uri,
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectIconURI,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_metadata_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(Some(
                                    random_ascii_alphanumeric_string(
                                        &mut rng,
                                        max_uri_len + 1..max_uri_len + 1000,
                                    )
                                    .into_bytes(),
                                )),
                                media_uri: DataOrNoVec::from(None),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_metadata_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Metadata URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let output_value: OutputValue = TokenData::from(NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
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
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let issuance_output = &outputs[0];

        assert_eq!(get_output_value(issuance_output).unwrap(), output_value);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_metadata_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
                                    .into_bytes(),
                                    description: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_desc_len,
                                    )
                                    .into_bytes(),
                                    ticker: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_ticker_len,
                                    )
                                    .into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri,
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        NftIssuanceV0 {
                            metadata: Metadata {
                                creator: Some(random_creator(&mut rng)),
                                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                                    .into_bytes(),
                                description: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_desc_len,
                                )
                                .into_bytes(),
                                ticker: random_ascii_alphanumeric_string(
                                    &mut rng,
                                    1..max_ticker_len,
                                )
                                .into_bytes(),
                                icon_uri: DataOrNoVec::from(None),
                                additional_metadata_uri: DataOrNoVec::from(None),
                                media_uri: DataOrNoVec::from(Some(
                                    random_ascii_alphanumeric_string(
                                        &mut rng,
                                        max_uri_len + 1..max_uri_len + 1000,
                                    )
                                    .into_bytes(),
                                )),
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        }
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorIncorrectMediaURI,
                        _,
                        _
                    ))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_uri_empty(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Media URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let output_value: OutputValue = TokenData::from(NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
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
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let issuance_output = &outputs[0];

        assert_eq!(get_output_value(issuance_output).unwrap(), output_value);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_uri_invalid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                            TxInput::from_utxo(outpoint_source_id.clone(), 0),
                            InputWitness::NoSignature(None),
                        )
                        .add_output(TxOutput::Transfer(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
                                    .into_bytes(),
                                    description: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_desc_len,
                                    )
                                    .into_bytes(),
                                    ticker: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_ticker_len,
                                    )
                                    .into_bytes(),
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri,
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process();

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMediaURI,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

fn new_block_with_media_hash(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    input_source_id: &OutPointSourceId,
    media_hash: Vec<u8>,
) -> Block {
    let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
    let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
    let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
    let name = random_ascii_alphanumeric_string(rng, 1..max_name_len).into_bytes();
    let description = random_ascii_alphanumeric_string(rng, 1..max_desc_len).into_bytes();
    let ticker = random_ascii_alphanumeric_string(rng, 1..max_ticker_len).into_bytes();
    let genesis_id = tf.genesis().get_id();
    let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

    tf.make_block_builder()
        .with_parent(genesis_id.into())
        .add_transaction(
            TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(input_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    NftIssuanceV0 {
                        metadata: Metadata {
                            creator: Some(random_creator(rng)),
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
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                .build(),
        )
        .build()
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_hash_too_short(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);
        let min_hash_len = tf.chainstate.get_chain_config().min_hash_len();

        // Media hash is too short
        for i in 0..min_hash_len {
            let media_hash = [rng.gen::<u8>()].repeat(i);

            let block =
                new_block_with_media_hash(&mut rng, &mut tf, &outpoint_source_id, media_hash);
            let result = tf.process_block(block, chainstate::BlockSource::Local);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::MediaHashTooShort,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_hash_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);
        let max_hash_len = tf.chainstate.get_chain_config().max_hash_len();

        // Media hash is too long
        for i in (max_hash_len + 1)..=(u8::MAX as usize) {
            let media_hash = [rng.gen::<u8>()].repeat(i);

            let block =
                new_block_with_media_hash(&mut rng, &mut tf, &outpoint_source_id, media_hash);
            let result = tf.process_block(block, chainstate::BlockSource::Local);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::MediaHashTooLong,
                            _,
                            _
                        ))
                    ))
                ))
            ));
        }
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_hash_valid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let min_hash_len = tf.chainstate.get_chain_config().min_hash_len();
        let max_hash_len = tf.chainstate.get_chain_config().max_hash_len();

        // Valid length cases
        for hash_size in [
            min_hash_len,
            min_hash_len + 4,
            min_hash_len + 8,
            min_hash_len + 12,
            min_hash_len + 16,
            min_hash_len + 20,
            max_hash_len,
        ] {
            let media_hash = [rng.gen::<u8>()].repeat(hash_size);

            let block = new_block_with_media_hash(
                &mut rng,
                &mut tf,
                &outpoint_source_id,
                media_hash.clone(),
            );
            let block_id = block.get_id();
            let _ = tf.process_block(block, chainstate::BlockSource::Local).unwrap();

            let block = tf.block(block_id);
            let outputs =
                tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
            let issuance_output = &outputs[0];

            match get_output_value(issuance_output).unwrap().token_data().unwrap() {
                TokenData::NftIssuance(nft) => {
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
fn nft_valid_case(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let valid_rfc3986_uri =
            b"https://something.com/?a:b.c_d-e~f!g/h?I#J[K]L@M$N&O/P'Q(R)S*T+U,V;W=Xyz".to_vec();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let output_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
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
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
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
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let issuance_output = &outputs[0];

        assert_eq!(
            get_output_value(issuance_output).unwrap(),
            output_value.into()
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_v0_issuance_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_nft_issuance(tf.chain_config(), &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::DeprecatedTokenOperationVersion(
                    TokenIssuanceVersion::V0,
                    tx_id,
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn only_ascii_alphanumeric_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let genesis_block_id = tf.best_block_id();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Try not ascii alphanumeric name
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let name = gen_text_with_non_ascii(c, &mut rng, max_name_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name,
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: Vec::new(),
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorNameHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // Try not ascii alphanumeric description
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let description = gen_text_with_non_ascii(c, &mut rng, max_desc_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description,
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorDescriptionHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // Try not ascii alphanumeric ticker
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let ticker = gen_text_with_non_ascii(c, &mut rng, max_ticker_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker,
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // valid case
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
    })
}
