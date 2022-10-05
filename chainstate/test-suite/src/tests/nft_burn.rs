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
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{token_id, Metadata, NftIssuanceV1, OutputValue, TokenData, TokenTransferV1},
    Destination, OutputPurpose, TxInput, TxOutput,
};
use common::primitives::Amount;
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    random_string,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_nft_valid_case(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Issuance
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
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
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Burn
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1(
                            common::chain::tokens::TokenBurnV1 {
                                token_id,
                                amount_to_burn: Amount::from_atoms(1),
                            },
                        )),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let first_burn_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // Try to transfer burned tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(first_burn_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(1),
                        })),
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
fn burn_nft_invalid_amount(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = TestBlockInfo::from_genesis(&tf.genesis()).txns[0].0.clone();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Issuance
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(genesis_outpoint_id, 0),
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
                                media_uri: None,
                                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                            },
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Burn more NFT than we have
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1(
                            common::chain::tokens::TokenBurnV1 {
                                token_id,
                                amount_to_burn: Amount::from_atoms(rng.gen_range(2..123)),
                            },
                        )),
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

        // Burn zero NFT
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenBurnV1(
                            common::chain::tokens::TokenBurnV1 {
                                token_id,
                                amount_to_burn: Amount::from_atoms(0),
                            },
                        )),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::BurnZeroTokens(_, _))
                ))
            ))
        ));
    })
}
