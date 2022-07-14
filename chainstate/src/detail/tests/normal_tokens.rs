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
    detail::{CheckBlockError, CheckBlockTransactionsError},
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
    primitives::{Amount, Idable},
};
use std::vec;

macro_rules! assert_token {
    ($block_index:expr, $err_name:ident) => {
        assert!(matches!(
            dbg!($block_index),
            Err(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::$err_name(
                    _,
                    _
                ))
            ))
        ));
    };
}

fn process_token(
    chainstate: &mut Chainstate,
    value: OutputValue,
) -> Result<Option<BlockIndex>, BlockError> {
    let prev_block_id = chainstate.get_best_block_id().unwrap().unwrap();
    let receiver = anyonecanspend_address();

    let prev_block = chainstate.get_block(prev_block_id.clone()).unwrap().unwrap();
    // Create a token issue transaction and block
    let inputs = vec![TxInput::new(
        prev_block.transactions()[0].get_id().into(),
        0,
        InputWitness::NoSignature(None),
    )];
    let outputs = vec![TxOutput::new(value, OutputPurpose::Transfer(receiver))];
    let block = Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).unwrap()],
        Some(prev_block_id),
        BlockTimestamp::from_int_seconds(prev_block.timestamp().as_int_seconds() + 1),
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
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value.clone()).unwrap().unwrap();
        let block = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &value);

        // Name is too long
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"TRY TO USE THE LONG NAME".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);

        // Doesn't exist name
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);

        // Name contain not alpha-numeric byte
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "💖".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);

        // Issue amount is too low
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(0),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);

        // Too many decimals
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(123456789),
            number_of_decimals: 123,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);

        // URI is too long
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.meta".repeat(1024).as_bytes().to_vec(),
        });
        assert_token!(process_token(&mut chainstate, value), TokenIssueFail);
    });
}

#[test]
fn token_transfer_test() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        // Issue a new token
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value.clone()).unwrap().unwrap();
        let block = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &value);

        // Transfer it
        let token_id = token_id(&block.transactions()[0]).unwrap();
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(123456789),
        });
        let _ = process_token(&mut chainstate, value).unwrap().unwrap();

        // Try to transfer exceed amount
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(987654321),
        });
        assert_token!(
            process_token(&mut chainstate, value),
            InsuffienceTokenValueInInputs
        );

        // Try to transfer token with wrong id
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id: TokenId::random(),
            amount: Amount::from_atoms(123456789),
        });
        assert_token!(process_token(&mut chainstate, value), NoTokenInInputs);

        // Try to transfer zero amount
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(0),
        });
        assert_token!(
            process_token(&mut chainstate, value),
            InsuffienceTokenValueInInputs
        );
    })
}

#[test]
fn couple_of_token_issuance_in_one_tx() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        let prev_block_id = chainstate.get_best_block_id().unwrap().unwrap();
        let receiver = anyonecanspend_address();
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let prev_block = chainstate.get_block(prev_block_id.clone()).unwrap().unwrap();
        // Create a token issue transaction and block
        let inputs = vec![TxInput::new(
            prev_block.transactions()[0].get_id().into(),
            0,
            InputWitness::NoSignature(None),
        )];
        let outputs = vec![
            TxOutput::new(value.clone(), OutputPurpose::Transfer(receiver.clone())),
            TxOutput::new(value, OutputPurpose::Transfer(receiver)),
        ];
        let block = Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).unwrap()],
            Some(prev_block_id),
            BlockTimestamp::from_int_seconds(prev_block.timestamp().as_int_seconds() + 1),
            ConsensusData::None,
        )
        .unwrap();

        // Process it
        assert_token!(
            chainstate.process_block(block, BlockSource::Local),
            TooManyTokenIssues
        );
    })
}

#[test]
fn token_issuance_with_insufficient_fee() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        let prev_block_id = chainstate.get_best_block_id().unwrap().unwrap();
        let receiver = anyonecanspend_address();
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let prev_block = chainstate.get_block(prev_block_id.clone()).unwrap().unwrap();
        // Create a token issue transaction and block
        let inputs = vec![TxInput::new(
            prev_block.transactions()[0].get_id().into(),
            0,
            InputWitness::NoSignature(None),
        )];

        let input_coins = match chainstate
            .get_block(chainstate.get_best_block_id().unwrap().unwrap())
            .unwrap()
            .unwrap()
            .transactions()[0]
            .outputs()[0]
            .value()
        {
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
            Some(prev_block_id),
            BlockTimestamp::from_int_seconds(prev_block.timestamp().as_int_seconds() + 1),
            ConsensusData::None,
        )
        .unwrap();

        // Process it
        assert_token!(
            chainstate.process_block(block, BlockSource::Local),
            TokenIssueFail
        );
    })
}

#[test]
fn transfer_few_tokens() {
    common::concurrency::model(|| {
        // Process token without errors
        let mut chainstate = setup_chainstate();
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://52292852472.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value.clone()).unwrap().unwrap();
        let block = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &value);

        // Another token
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDT".to_vec(),
            amount_to_issue: Amount::from_atoms(123456789),
            number_of_decimals: 1,
            metadata_uri: b"https://123456789.org".to_vec(),
        });
        let _ = process_token(&mut chainstate, value).unwrap().unwrap();

        // One more token
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"PAX".to_vec(),
            amount_to_issue: Amount::from_atoms(987654321),
            number_of_decimals: 1,
            metadata_uri: b"https://987654321.com".to_vec(),
        });
        let _ = process_token(&mut chainstate, value).unwrap().unwrap();
    })
}

#[test]
fn test_burn_tokens() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        // Issue a new token
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value.clone()).unwrap().unwrap();
        let block = chainstate.get_block(block_index.block_id().clone()).unwrap().unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &value);

        // Transfer it
        let token_id = token_id(&block.transactions()[0]).unwrap();
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(123456789),
        });
        let _ = process_token(&mut chainstate, value).unwrap().unwrap();

        // Try to burn it
        let value = OutputValue::Asset(AssetData::TokenBurnV1 {
            token_id,
            amount_to_burn: Amount::from_atoms(987654321),
        });
        let _ = process_token(&mut chainstate, value).unwrap().unwrap();

        // Try to transfer burned tokens
        let value = OutputValue::Asset(AssetData::TokenTransferV1 {
            token_id,
            amount: Amount::from_atoms(123456789),
        });
        assert_token!(process_token(&mut chainstate, value), NoTokenInInputs);


        // Try burn more than we have in input
        // Burn 50% and 50% transfer
        // Burn 50% and don't add utxo for rest
        // Burn 100% and then try to transfer it
    })
}
