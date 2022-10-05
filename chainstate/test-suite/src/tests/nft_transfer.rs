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
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{TestBlockInfo, TestFramework, TransactionBuilder};
use common::{
    chain::{
        signature::inputsig::InputWitness,
        tokens::{
            token_id, Metadata, NftIssuanceV1, OutputValue, TokenData, TokenId, TokenTransferV1,
        },
        Destination, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    random_string,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_transfer_wrong_id(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: None,
                additional_metadata_uri: None,
                media_uri: None,
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }));

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
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
        let block = tf.block(*block_index.block_id());
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer NFT with wrong ID
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id: TokenId::random(),
                            amount: Amount::from_atoms(1),
                        })),
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
fn nft_invalid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: None,
                additional_metadata_uri: None,
                media_uri: None,
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }));

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
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
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer 0 NFT
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(0),
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
                    CheckBlockTransactionsError::TokensError(TokensError::TransferZeroTokens(_, _))
                ))
            ))
        ));

        // Try to transfer more NFT than we have in input
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(rng.gen_range(2..123)),
                        })),
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
fn spend_different_nft_than_one_in_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Issuance a few different NFT
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();
        let output_value = OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: None,
                additional_metadata_uri: None,
                media_uri: None,
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }));
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
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let first_issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
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
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id: first_token_id,
                            amount: Amount::from_atoms(1),
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
                            metadata: Metadata {
                                creator: random_creator(),
                                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
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
        let _ = token_id(block.transactions()[0].transaction()).unwrap();

        // Try to spend 2 NFTs but use one ID

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
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id: first_token_id,
                            amount: Amount::from_atoms(2),
                        })),
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
fn nft_valid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = OutputValue::Token(TokenData::NftIssuanceV1(NftIssuanceV1 {
            metadata: Metadata {
                creator: random_creator(),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: None,
                additional_metadata_uri: None,
                media_uri: None,
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }));

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
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
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer exceed amount

        let transfer_value = OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(1),
        }));
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        transfer_value.clone(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(block_index.block_height(), BlockHeight::from(2));

        let block = tf.block(*block_index.block_id());
        let outputs = &TestBlockInfo::from_block(&block).txns[0].1;
        let transfer_output = &outputs[0];

        assert_eq!(transfer_output.value(), &transfer_value);
    })
}
