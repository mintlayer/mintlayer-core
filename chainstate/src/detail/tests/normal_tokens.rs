// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Sinitsyn

use super::{anyonecanspend_address, setup_chainstate};
use crate::{
    detail::{
        spend_cache::error::StateUpdateError, tests::TestBlockInfo, CheckBlockError,
        CheckBlockTransactionsError, TokensError,
    },
    BlockError, BlockSource, Chainstate,
};
use chainstate_types::block_index::BlockIndex;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        signature::inputsig::InputWitness,
        tokens::{token_id, AssetData, OutputValue, TokenId},
        OutputPurpose, Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount},
};
use std::vec;

fn process_token(
    chainstate: &mut Chainstate,
    values: Vec<OutputValue>,
) -> Result<Option<BlockIndex>, BlockError> {
    let receiver = anyonecanspend_address();
    let parent_block_id = chainstate.get_best_block_id().unwrap();
    let test_block_info = TestBlockInfo::from_id(chainstate, parent_block_id);

    // Create a token issue transaction and block
    let inputs = test_block_info
        .txns
        .iter()
        .flat_map(|(outpoint_source_id, outputs)| {
            outputs
                .iter()
                .enumerate()
                .map(|(output_index, _output)| {
                    TxInput::new(
                        outpoint_source_id.clone(),
                        output_index.try_into().unwrap(),
                        InputWitness::NoSignature(None),
                    )
                })
                .collect::<Vec<TxInput>>()
        })
        .collect();

    let outputs: Vec<TxOutput> = values
        .into_iter()
        .map(|value| TxOutput::new(value, OutputPurpose::Transfer(receiver.clone())))
        .collect();

    let block = Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).unwrap()],
        parent_block_id,
        BlockTimestamp::from_duration_since_epoch(time::get()),
        ConsensusData::None,
    )
    .unwrap();

    // Process it
    chainstate.process_block(block, BlockSource::Local)
}

#[test]
fn token_issue_test() {
    common::concurrency::model(|| {
        // Process token without errors
        let mut chainstate = setup_chainstate();
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        let block_index = process_token(&mut chainstate, values.clone()).unwrap().unwrap();
        let block = chainstate.get_block(*block_index.block_id()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &values[0]);

        // Ticker is too long
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"TRY TO USE THE LONG NAME".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorIncorrectTicker(_, _)
                    )
                )
            ))
        ));

        // Doesn't exist ticker
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorIncorrectTicker(_, _)
                    )
                )
            ))
        ));

        // Ticker contain not alpha-numeric byte
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "💖".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorIncorrectTicker(_, _)
                    )
                )
            ))
        ));

        // Issue amount is too low
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(0),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorIncorrectAmount(_, _)
                    )
                )
            ))
        ));

        // Too many decimals
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(123456789),
            number_of_decimals: 123,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorTooManyDecimals(_, _)
                    )
                )
            ))
        ));

        // URI is too long
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.meta".repeat(1024).as_bytes().to_vec(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::IssueErrorIncorrectMetadataURI(_, _)
                    )
                )
            ))
        ));
    });
}

#[test]
fn token_transfer_test() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        // Issue a new token
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        let block_index = process_token(&mut chainstate, values.clone()).unwrap().unwrap();
        let block = chainstate.get_block(*block_index.block_id()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &values[0]);

        // Transfer it
        let token_id = token_id(&block.transactions()[0]).unwrap();
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(123456789),
        })];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();

        // Try to transfer exceed amount
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(987654321),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::InsuffienceTokenValueInInputs(_, _))
            ))
        ));

        // Try to transfer token with wrong id
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id: TokenId::random(),
            amount: Amount::from_atoms(123456789),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::NoTokenInInputs(_, _))
            ))
        ));

        // Try to transfer zero amount
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(0),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(TokensError::TransferZeroTokens(
                        _,
                        _
                    ))
                )
            ))
        ));
    })
}

#[test]
fn couple_of_token_issuance_in_one_tx() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        let parent_block_id = chainstate.get_best_block_id().unwrap();
        let test_block_info = TestBlockInfo::from_id(&chainstate, parent_block_id);
        let receiver = anyonecanspend_address();
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        // Create a token issue transaction and block
        let inputs = vec![TxInput::new(
            test_block_info.txns[0].0.clone(),
            0,
            InputWitness::NoSignature(None),
        )];
        let outputs = vec![
            TxOutput::new(value.clone(), OutputPurpose::Transfer(receiver.clone())),
            TxOutput::new(value, OutputPurpose::Transfer(receiver)),
        ];
        let block = Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).unwrap()],
            parent_block_id,
            BlockTimestamp::from_duration_since_epoch(time::get()),
            ConsensusData::None,
        )
        .unwrap();

        // Process it
        assert!(matches!(
            chainstate.process_block(block, BlockSource::Local),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTokensError(
                        TokensError::MultipleTokenIssuanceInTransaction(_, _)
                    )
                )
            ))
        ));
    })
}

#[test]
fn token_issuance_with_insufficient_fee() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let parent_block_id = chainstate.get_best_block_id().unwrap();
        let test_block_info = TestBlockInfo::from_id(&chainstate, parent_block_id);

        let receiver = anyonecanspend_address();
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        // Create a token issue transaction and block
        let inputs = vec![TxInput::new(
            test_block_info.txns[0].0.clone(),
            0,
            InputWitness::NoSignature(None),
        )];

        let input_coins = match test_block_info.txns[0].1[0].value() {
            OutputValue::Coin(coin) => *coin,
            OutputValue::Asset(_) => unreachable!(),
        };

        let outputs = vec![
            TxOutput::new(value, OutputPurpose::Transfer(receiver.clone())),
            TxOutput::new(
                OutputValue::Coin((input_coins - Amount::from_atoms(1)).unwrap()),
                OutputPurpose::Transfer(receiver),
            ),
        ];
        let block = Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).unwrap()],
            parent_block_id,
            BlockTimestamp::from_duration_since_epoch(time::get()),
            ConsensusData::None,
        )
        .unwrap();

        // Process it
        assert!(matches!(
            chainstate.process_block(block, BlockSource::Local),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::InsuffienceTokenFees(_, _))
            ))
        ));
    })
}

#[test]
fn transfer_tokens() {
    common::concurrency::model(|| {
        const TOTAL_TOKEN_VALUE: Amount = Amount::from_atoms(52292852472);

        // Process token without errors
        let mut chainstate = setup_chainstate();
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: TOTAL_TOKEN_VALUE,
            number_of_decimals: 1,
            metadata_uri: b"https://52292852472.meta".to_vec(),
        })];
        let block_index = process_token(&mut chainstate, values.clone()).unwrap().unwrap();
        let block = chainstate.get_block(*block_index.block_id()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &values[0]);
        let token_id = token_id(&block.transactions()[0]).unwrap();

        // Split token in outputs
        let values = vec![
            OutputValue::Asset(AssetData::TokenTransferV1 {
                token_id,
                amount: (TOTAL_TOKEN_VALUE - Amount::from_atoms(123456)).unwrap(),
            }),
            OutputValue::Asset(AssetData::TokenTransferV1 {
                token_id,
                amount: Amount::from_atoms(123456),
            }),
        ];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();

        // Collect these in one output
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: TOTAL_TOKEN_VALUE,
        })];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();
    })
}

#[test]
fn test_burn_tokens() {
    common::concurrency::model(|| {
        const ISSUED_FUNDS: Amount = Amount::from_atoms(123456788);
        const HALF_ISSUED_FUNDS: Amount = Amount::from_atoms(61728394);

        let mut chainstate = setup_chainstate();
        // Issue a new token
        let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: ISSUED_FUNDS,
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        })];
        let block_index = process_token(&mut chainstate, values.clone()).unwrap().unwrap();
        let block = chainstate.get_block(*block_index.block_id()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &values[0]);

        // Transfer it
        let token_id = token_id(&block.transactions()[0]).unwrap();
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: ISSUED_FUNDS,
        })];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();

        // Try burn more than we have in input
        let values = vec![OutputValue::Asset(AssetData::TokenBurnV1 {
            token_id,
            amount_to_burn: (ISSUED_FUNDS * 2).unwrap(),
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::InsuffienceTokenValueInInputs(_, _))
            ))
        ));

        // Burn 50% and don't add utxo for the rest
        let values = vec![OutputValue::Asset(AssetData::TokenBurnV1 {
            token_id,
            amount_to_burn: HALF_ISSUED_FUNDS,
        })];
        assert!(matches!(
            process_token(&mut chainstate, values),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::SomeTokensLost(_, _))
            ))
        ));

        // Burn 50% and 50% transfer
        let values = vec![
            OutputValue::Asset(AssetData::TokenBurnV1 {
                token_id,
                amount_to_burn: HALF_ISSUED_FUNDS,
            }),
            OutputValue::Asset(AssetData::TokenTransferV1 {
                token_id,
                amount: HALF_ISSUED_FUNDS,
            }),
        ];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();

        // Try to burn it all
        let values = vec![OutputValue::Asset(AssetData::TokenBurnV1 {
            token_id,
            amount_to_burn: HALF_ISSUED_FUNDS,
        })];
        let _ = process_token(&mut chainstate, values).unwrap().unwrap();

        // Try to transfer burned tokens
        let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(123456789),
        })];
        assert!(matches!(
            dbg!(process_token(&mut chainstate, values)),
            Err(BlockError::StateUpdateFailed(
                StateUpdateError::TokensError(TokensError::NoTokenInInputs(_, _))
            ))
        ));
    })
}

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
// B1, your check for whether that output is spent will simply yield a wrong result,
// because it was spent in B1 but isn't spent in your chain. As you see, knowing whether
// that output is spent depends on the current tip, and that's why check_block doesn't
// look into the history, because the database state is not compatible with every block
// we check.
// #[test]
// fn test_reorg_and_try_to_double_spend_tokens() {
//     common::concurrency::model(|| {
//         const ISSUED_FUNDS: Amount = Amount::from_atoms(1_000_000);

//         // Issue a new token
//         let mut chainstate = setup_chainstate();
//         let values = vec![OutputValue::Asset(AssetData::TokenIssuanceV1 {
//             token_ticker: b"USDC".to_vec(),
//             amount_to_issue: ISSUED_FUNDS,
//             number_of_decimals: 1,
//             metadata_uri: b"https://some_site.meta".to_vec(),
//         })];
//         let block_index = process_token(&mut chainstate, values.clone()).unwrap().unwrap();
//         let block_a = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();
//         assert_eq!(block_a.transactions()[0].outputs()[0].value(), &values[0]);
//         let token_id = token_id(&block_a.transactions()[0]).unwrap();

//         // B1 - burn all tokens in mainchain
//         let values = vec![OutputValue::Asset(AssetData::TokenBurnV1 {
//             token_id,
//             amount_to_burn: ISSUED_FUNDS,
//         })];
//         let block_index = process_token(&mut chainstate, values).unwrap().unwrap();
//         let block_b1 = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();

//         // Try to transfer spent tokens
//         let values = vec![OutputValue::Asset(AssetData::TokenTransferV1 {
//             token_id,
//             amount: ISSUED_FUNDS,
//         })];
//         let _ = process_token(&mut chainstate, values).unwrap().unwrap();

//         // Second chain - B2
//     })
// }
