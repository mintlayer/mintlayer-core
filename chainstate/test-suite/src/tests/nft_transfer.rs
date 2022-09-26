use chainstate::{BlockError, ChainstateError, TokensError};
use chainstate::{CheckBlockError, CheckBlockTransactionsError, ConnectTransactionError};
use chainstate_test_framework::{TestBlockInfo, TestFramework, TransactionBuilder};
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{
        token_id, Metadata, NftIssuanceV1, OutputValue, TokenCreator, TokenData, TokenId,
        TokenTransferV1,
    },
    Destination, OutputPurpose, TxInput, TxOutput,
};
use common::primitives::Amount;
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::distributions::uniform::SampleRange;
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

// FIXME(nft_issuance): This is the copy of function from check block. Remove copy and use this func from more appropriate place.
fn random_creator() -> TokenCreator {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    TokenCreator::from(public_key)
}

//FIXME(nft_issuance): Move it in super mod and use for all tokens tests
fn random_string<R: SampleRange<usize>>(rng: &mut impl Rng, range_len: R) -> String {
    use crypto::random::distributions::{Alphanumeric, DistString};
    if range_len.is_empty() {
        return String::new();
    }
    let len = rng.gen_range(range_len);
    Alphanumeric.sample_string(rng, len)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_transfer_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = make_seedable_rng(seed);
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
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
                    .add_input(TxInput::new(
                        genesis_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
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
        let token_id = token_id(&block.transactions()[0]).unwrap();
        assert_eq!(block.transactions()[0].outputs()[0].value(), &output_value);
        let issuance_outpoint_id = TestBlockInfo::from_block(&block).txns[0].0.clone();

        // attempt double-spend
        let result = tf
            .make_block_builder()
            .with_parent((*block_index.block_id()).into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        genesis_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        output_value,
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

        // Try to transfer exceed amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id,
                            amount: Amount::from_atoms(total_funds.into_atoms() + 1),
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            dbg!(result),
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));

        // Try to transfer token with wrong id
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id: TokenId::random(),
                            amount: total_funds,
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::MissingOutputOrSpent)
            ))
        ));

        // Try to transfer zero amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id.clone(),
                        0,
                        InputWitness::NoSignature(None),
                    ))
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

        // Valid case - Transfer tokens
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(TxInput::new(
                        issuance_outpoint_id,
                        0,
                        InputWitness::NoSignature(None),
                    ))
                    .add_output(TxOutput::new(
                        OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                            token_id,
                            amount: total_funds,
                        })),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
    })
}

//FIXME(nft_issuance): NFT transfers checks
