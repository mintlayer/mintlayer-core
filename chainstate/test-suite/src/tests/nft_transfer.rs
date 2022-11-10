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
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::primitives::Idable;
use common::{
    chain::{
        signature::inputsig::InputWitness,
        tokens::{token_id, Metadata, NftIssuance, OutputValue, TokenData, TokenId, TokenTransfer},
        Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::random::Rng;
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    nft_utils::random_creator,
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
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuance {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(genesis_outpoint_id, 0),
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
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        assert_eq!(
            block.transactions()[0].outputs()[0].value(),
            &output_value.into()
        );
        assert!(tf
            .outputs_from_genblock(block.get_id().into())
            .contains_key(&issuance_outpoint_id));

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
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id: TokenId::random_using(&mut rng),
                            amount: Amount::from_atoms(1),
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
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuance {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(genesis_outpoint_id, 0),
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
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx.clone())
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();
        assert_eq!(block.transactions()[0], tx);
        assert_eq!(tx.outputs()[0].value(), &output_value.into());

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
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(rng.gen_range(2..123)),
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
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = NftIssuance {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }
        .into();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let tx = TransactionBuilder::new()
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
            .build();
        let first_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let first_token_id = token_id(block.transactions()[0].transaction()).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let tx = TransactionBuilder::new()
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
                    amount: Amount::from_atoms(1),
                })
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .add_output(TxOutput::new(
                NftIssuance {
                    metadata: Metadata {
                        creator: Some(random_creator()),
                        name: random_string(&mut rng, 1..max_name_len).into_bytes(),
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
            .add_output(TxOutput::new(
                OutputValue::Coin(token_min_issuance_fee),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(token_min_issuance_fee),
                OutputPurpose::Burn,
            ))
            .build();
        let second_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
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
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id: first_token_id,
                            amount: Amount::from_atoms(2),
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
fn nft_valid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuance {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(genesis_outpoint_id, 0),
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
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();
        assert_eq!(
            block.transactions()[0].outputs()[0].value(),
            &output_value.into()
        );

        // Valid case
        let transfer_value = TokenData::TokenTransfer(TokenTransfer {
            token_id,
            amount: Amount::from_atoms(1),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        transfer_value.clone().into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(block_index.block_height(), BlockHeight::from(2));

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let transfer_output = &outputs[0];

        assert_eq!(transfer_output.value(), &transfer_value.into());
    })
}
