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

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::primitives::{BlockHeight, Idable};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{is_rfc3986_valid_symbol, Metadata, NftIssuance, NftIssuanceV0, TokenId},
        Block, ChainstateUpgradeBuilder, Destination, GenBlock, OutPointSourceId,
        TokenIssuanceVersion, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::Id,
};
use randomness::{CryptoRng, Rng};
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    gen_text_with_non_ascii,
    nft_utils::{random_creator, random_nft_issuance, random_token_issuance_v1},
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::{error::TokenIssuanceError, CheckTransactionError};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_name_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidNameLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidNameLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorNameHasNoneAlphaNumericChar,
                                _,
                            ))
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
fn nft_ticker_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidTickerLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                                    ticker: vec![],
                                    icon_uri: DataOrNoVec::from(None),
                                    additional_metadata_uri: DataOrNoVec::from(None),
                                    media_uri: DataOrNoVec::from(None),
                                    media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                                },
                            }
                            .into(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidTickerLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                                _,
                            ))
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
fn nft_description_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidDescriptionLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
                            NftIssuanceV0 {
                                metadata: Metadata {
                                    creator: Some(random_creator(&mut rng)),
                                    name: random_ascii_alphanumeric_string(
                                        &mut rng,
                                        1..max_name_len,
                                    )
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidDescriptionLength,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorDescriptionHasNonAlphaNumericChar,
                                _,
                            ))
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
fn nft_icon_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectIconURI,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let metadata = Metadata {
            creator: Some(random_creator(&mut rng)),
            name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
            description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len).into_bytes(),
            ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
            icon_uri: DataOrNoVec::from(Some(vec![])),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
                            NftIssuanceV0 {
                                metadata: metadata.clone(),
                            }
                            .into(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            block_index.block_height(),
            common::primitives::BlockHeight::from(1)
        );

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();

        match &outputs[0] {
            TxOutput::IssueNft(_, nft, _) => match nft.as_ref() {
                NftIssuance::V0(nft) => assert_eq!(nft.metadata, metadata),
            },
            _ => panic!("unexpected output"),
        };
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorIncorrectIconURI,
                                _,
                            ))
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
fn nft_metadata_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        // Metadata URI is too long
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                            _,
                        ))
                    )
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
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        // Metadata URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let metadata = Metadata {
            creator: Some(random_creator(&mut rng)),
            name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
            description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len).into_bytes(),
            ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(Some(vec![])),
            media_uri: DataOrNoVec::from(None),
            media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
                            NftIssuanceV0 {
                                metadata: metadata.clone(),
                            }
                            .into(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            block_index.block_height(),
            common::primitives::BlockHeight::from(1)
        );

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();

        match &outputs[0] {
            TxOutput::IssueNft(_, nft, _) => match nft.as_ref() {
                NftIssuance::V0(nft) => assert_eq!(nft.metadata, metadata),
            },
            _ => panic!("unexpected output"),
        };
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                                _,
                            ))
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
fn nft_media_uri_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        // Media URI is too long
        let max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
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
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMediaURI,
                            _,
                        ))
                    )
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        // Media URI is empty
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let metadata = Metadata {
            creator: Some(random_creator(&mut rng)),
            name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
            description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len).into_bytes(),
            ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(Some(vec![])),
            media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        };

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
                            NftIssuanceV0 {
                                metadata: metadata.clone(),
                            }
                            .into(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            block_index.block_height(),
            common::primitives::BlockHeight::from(1)
        );

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();

        match &outputs[0] {
            TxOutput::IssueNft(_, nft, _) => match nft.as_ref() {
                NftIssuance::V0(nft) => assert_eq!(nft.metadata, metadata),
            },
            _ => panic!("unexpected output"),
        };
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

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
                        .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
                        .add_output(TxOutput::IssueNft(
                            token_id,
                            Box::new(
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
                            ),
                            Destination::AnyoneCanSpend,
                        ))
                        .build(),
                )
                .build_and_process(&mut rng);

            assert!(matches!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorIncorrectMediaURI,
                                _,
                            ))
                        )
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
    let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();
    let token_min_issuance_fee =
        tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
    let tx_first_input = TxInput::from_utxo(input_source_id.clone(), 0);
    let token_id = TokenId::from_tx_input(&tx_first_input);

    tf.make_block_builder()
        .with_parent(genesis_id)
        .add_transaction(
            TransactionBuilder::new()
                .add_input(tx_first_input, InputWitness::NoSignature(None))
                .add_output(TxOutput::IssueNft(
                    token_id,
                    Box::new(NftIssuance::V0(NftIssuanceV0 {
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
                    })),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                .build(),
        )
        .build(rng)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_media_hash_too_short(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::MediaHashTooShort,
                                _,
                            ))
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
fn nft_media_hash_too_long(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
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
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::MediaHashTooLong,
                                _,
                            ))
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
fn nft_media_hash_valid(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

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

            match &outputs[0] {
                TxOutput::IssueNft(_, nft, _) => match nft.as_ref() {
                    NftIssuance::V0(nft) => assert_eq!(nft.metadata.media_hash(), &media_hash),
                },
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
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let valid_rfc3986_uri =
            b"https://something.com/?a:b.c_d-e~f!g/h?I#J[K]L@M$N&O/P'Q(R)S*T+U,V;W=Xyz".to_vec();
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let metadata = Metadata {
            creator: Some(random_creator(&mut rng)),
            name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
            description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len).into_bytes(),
            ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
            icon_uri: DataOrNoVec::from(Some(valid_rfc3986_uri.clone())),
            additional_metadata_uri: DataOrNoVec::from(Some(valid_rfc3986_uri.clone())),
            media_uri: DataOrNoVec::from(Some(valid_rfc3986_uri)),
            media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        };

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(
                            NftIssuanceV0 {
                                metadata: metadata.clone(),
                            }
                            .into(),
                        ),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            block_index.block_height(),
            common::primitives::BlockHeight::from(1)
        );

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();

        match &outputs[0] {
            TxOutput::IssueNft(_, nft, _) => match nft.as_ref() {
                NftIssuance::V0(nft) => assert_eq!(nft.metadata, metadata),
            },
            _ => panic!("unexpected output"),
        };
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

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

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

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::DeprecatedTokenOperationVersion(
                            TokenIssuanceVersion::V0,
                            tx_id,
                        )
                    )
                )
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
        let genesis_block_id = tf.best_block_id();

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
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
        let tx_first_input = TxInput::from_utxo(genesis_block_id.into(), 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorNameHasNoneAlphaNumericChar,
                            tx_id,
                        ))
                    )
                )
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
        let tx_first_input = TxInput::from_utxo(genesis_block_id.into(), 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorDescriptionHasNonAlphaNumericChar,
                            tx_id,
                        ))
                    )
                )
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
        let tx_first_input = TxInput::from_utxo(genesis_block_id.into(), 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                            tx_id,
                        ))
                    )
                )
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

        let tx = TransactionBuilder::new()
            .add_input(tx_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_token_id_mismatch(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let invalid_token_id = TokenId::from_tx_input(
            &UtxoOutPoint::new(outpoint_source_id.clone(), rng.gen_range(1..100)).into(),
        );
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let valid_token_id = TokenId::from_tx_input(&tx_first_input);

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let nft_issuance = random_nft_issuance(tf.chain_config(), &mut rng);

        let invalid_tx = TransactionBuilder::new()
            .add_input(tx_first_input.clone(), InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                invalid_token_id,
                Box::new(nft_issuance.clone().into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let invalid_tx_id = invalid_tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(invalid_tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::IssueError(
                    TokenIssuanceError::TokenIdMismatch(invalid_token_id, valid_token_id),
                    invalid_tx_id
                ))
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        valid_token_id,
                        Box::new(nft_issuance.into()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_nft_twice_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let nft_issuance1 = random_nft_issuance(tf.chain_config(), &mut rng);
        let nft_issuance2 = random_nft_issuance(tf.chain_config(), &mut rng);

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(nft_issuance1.into()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(nft_issuance2.into()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        (token_min_issuance_fee * 2).unwrap(),
                    )))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(
                            TokensError::MultipleTokenIssuanceInTransaction(_)
                        )
                    )
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_nft_and_fungible_token_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
        let outpoint_source_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let tx_first_input = TxInput::from_utxo(outpoint_source_id, 0);
        let token_id = TokenId::from_tx_input(&tx_first_input);

        let nft_issuance = random_nft_issuance(tf.chain_config(), &mut rng);
        let fungible_token_issuance =
            random_token_issuance_v1(tf.chain_config(), Destination::AnyoneCanSpend, &mut rng);

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(tx_first_input, InputWitness::NoSignature(None))
                    .add_output(TxOutput::IssueNft(
                        token_id,
                        Box::new(nft_issuance.into()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueFungibleToken(Box::new(
                        common::chain::tokens::TokenIssuance::V1(fungible_token_issuance),
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        (token_min_issuance_fee * 2).unwrap(),
                    )))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(
                            TokensError::MultipleTokenIssuanceInTransaction(_)
                        )
                    )
                ))
            ))
        ));
    })
}
