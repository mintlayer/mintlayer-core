use std::vec;

use crate::{
    detail::{CheckBlockError, CheckBlockTransactionsError},
    BlockError, BlockSource, Chainstate,
};

use super::{anyonecanspend_address, setup_chainstate};
use chainstate_types::block_index::BlockIndex;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, ConsensusData},
        signature::inputsig::InputWitness,
        token_id, AssetData, OutputPurpose, OutputValue, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};

fn assert_token_issue(block_index: Result<Option<BlockIndex>, BlockError>) {
    assert!(matches!(
        block_index,
        Err(BlockError::CheckBlockFailed(
            CheckBlockError::CheckTransactionFailed(
                CheckBlockTransactionsError::TokenIssueTransactionIncorrect(_, _)
            )
        ))
    ));
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
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);

        // Doesn't exist name
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);

        // Name contain not alpha-numeric byte
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "💖".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);

        // Issue amount is too low
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(0),
            number_of_decimals: 1,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);

        // Too many decimals
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: "USDT".as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(123456789),
            number_of_decimals: 123,
            metadata_uri: b"https://some_site.meta".to_vec(),
        });
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);

        // URI is too long
        let value = OutputValue::Asset(AssetData::TokenIssuanceV1 {
            token_ticker: b"USDC".to_vec(),
            amount_to_issue: Amount::from_atoms(52292852472),
            number_of_decimals: 1,
            metadata_uri: "https://some_site.meta".repeat(1024).as_bytes().to_vec(),
        });
        let block_index = process_token(&mut chainstate, value);
        assert_token_issue(block_index);
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
    })
}
