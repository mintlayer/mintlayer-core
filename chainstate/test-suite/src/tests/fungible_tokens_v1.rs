// Copyright (c) 2023 RBB S.r.l
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
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_storage::BlockchainStorageRead;
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::tokens::{
    token_id, TokenId, TokenIssuanceV1, TokenIssuanceVersioned, TokenTotalSupply,
};
use common::chain::{Block, GenBlock, UtxoOutPoint};
use common::primitives::signed_amount::SignedAmount;
use common::primitives::Id;
use common::{
    chain::{
        output_value::OutputValue, signature::inputsig::InputWitness, AccountNonce,
        AccountSpending, Destination, OutPointSourceId, TokenOutput, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string,
};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::error::TokenIssuanceError;

fn make_issuance(rng: &mut impl Rng, supply: TokenTotalSupply) -> TokenIssuanceVersioned {
    TokenIssuanceVersioned::V1(TokenIssuanceV1 {
        token_ticker: random_string(rng, 1..5).as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: random_string(rng, 1..1024).as_bytes().to_vec(),
        supply_limit: supply,
        reissuance_controller: Destination::AnyoneCanSpend,
    })
}

fn issue_token_from_block(
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_input_outpoint: UtxoOutPoint,
    issuance: TokenIssuanceVersioned,
) -> (TokenId, Id<Block>, UtxoOutPoint) {
    let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::Utxo(utxo_input_outpoint),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((token_min_issuance_fee * 10).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
            issuance.clone(),
        ))))
        .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
        .build();
    let token_id = token_id(tx.transaction()).unwrap();
    let tx_id = tx.transaction().get_id();
    let block = tf.make_block_builder().add_transaction(tx).with_parent(parent_block_id).build();
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();

    (token_id, block_id, UtxoOutPoint::new(tx_id.into(), 0))
}

// Returns created token id and out point with change
fn issue_token_from_genesis(
    rng: &mut impl Rng,
    tf: &mut TestFramework,
    supply: TokenTotalSupply,
) -> (TokenId, Id<Block>, UtxoOutPoint) {
    let utxo_input_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);
    let issuance = make_issuance(rng, supply);
    issue_token_from_block(
        tf,
        tf.genesis().get_id().into(),
        utxo_input_outpoint,
        issuance,
    )
}
fn mint_tokens_in_block(
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_to_pay_fee: UtxoOutPoint,
    token_id: TokenId,
    amount_to_mint: Amount,
) -> Id<Block> {
    let token_min_supply_change_fee =
        tf.chainstate.get_chain_config().token_min_supply_change_fee();

    let nonce = BlockchainStorageRead::get_account_nonce_count(
        &tf.storage,
        common::chain::AccountType::TokenSupply(token_id),
    )
    .unwrap()
    .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

    let block = tf
        .make_block_builder()
        .add_transaction(
            TransactionBuilder::new()
                .add_input(
                    TxInput::from_account(
                        nonce,
                        AccountSpending::TokenSupply(token_id, amount_to_mint),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_input(utxo_to_pay_fee.into(), InputWitness::NoSignature(None))
                .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                    token_id,
                    amount_to_mint,
                    Destination::AnyoneCanSpend,
                )))
                .add_output(TxOutput::Burn(OutputValue::Coin(
                    token_min_supply_change_fee,
                )))
                .build(),
        )
        .with_parent(parent_block_id.into())
        .build();
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();
    block_id
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let token_max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let token_max_dec_count = tf.chainstate.get_chain_config().token_max_dec_count();
        let token_max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        let mut process_block_with_issuance = |issuance: TokenIssuanceVersioned| {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(outpoint_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
                    issuance,
                ))))
                .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                .build();
            let tx_id = tx.transaction().get_id();
            let block = tf.make_block_builder().add_transaction(tx).build();
            let block_id = block.get_id();
            let result = tf.process_block(block, BlockSource::Local);
            (result, tx_id, block_id)
        };

        // Ticker is too long
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 10..u16::MAX as usize).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        // Ticker doesn't exist
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorInvalidTickerLength,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        {
            // try all possible chars for ticker and ensure everything fails except for alphanumeric chars
            for c in u8::MIN..u8::MAX {
                // if c is alphanumeric, then this doesn't produce an error, skip it
                if c.is_ascii_alphanumeric() {
                    continue;
                }

                let token_ticker = gen_text_with_non_ascii(c, &mut rng, token_max_ticker_len);

                // Ticker contain non alpha-numeric char
                let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                    token_ticker,
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                    supply_limit: TokenTotalSupply::Unlimited,
                    reissuance_controller: Destination::AnyoneCanSpend,
                });
                let (result, tx_id, block_id) = process_block_with_issuance(issuance);

                assert_eq!(
                    result,
                    Err(ChainstateError::ProcessBlockError(
                        BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                            CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                                tx_id,
                                block_id
                            ))
                        ))
                    ))
                );
            }
        }

        // Too many decimals
        {
            let decimals_count_to_use = token_max_dec_count + 1;

            let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: decimals_count_to_use,
                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                supply_limit: TokenTotalSupply::Unlimited,
                reissuance_controller: Destination::AnyoneCanSpend,
            });
            let (result, tx_id, block_id) = process_block_with_issuance(issuance);
            assert_eq!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorTooManyDecimals,
                            tx_id,
                            block_id
                        ))
                    ))
                ))
            );
        }

        // URI is too long
        {
            let uri_len_range_to_use = (token_max_uri_len + 1)..u16::MAX as usize;

            let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_string(&mut rng, uri_len_range_to_use).as_bytes().to_vec(),
                supply_limit: TokenTotalSupply::Unlimited,
                reissuance_controller: Destination::AnyoneCanSpend,
            });
            let (result, tx_id, block_id) = process_block_with_issuance(issuance);
            assert_eq!(
                result,
                Err(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                            tx_id,
                            block_id
                        ))
                    ))
                ))
            );
        }

        // URI contain non alpha-numeric char
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let (result, tx_id, block_id) = process_block_with_issuance(issuance);
        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::IssueError(
                        TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                        tx_id,
                        block_id
                    ))
                ))
            ))
        );

        // Valid case
        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(outpoint_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
                issuance.clone(),
            ))))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let token_id = token_id(tx.transaction()).unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
        let expected_token_data = tokens_accounting::TokenData::FungibleToken(issuance.into());
        assert_eq!(actual_token_data, Some(expected_token_data));

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, None);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_not_enough_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
                        issuance.clone(),
                    ))))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        (token_min_issuance_fee - Amount::from_atoms(1)).unwrap(),
                    )))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_cannot_be_spent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let issuance = TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        });
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
                issuance.clone(),
            ))))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().token_min_issuance_fee(),
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
                        issuance.clone(),
                    ))))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(common::chain::UtxoOutPoint::new(
                    tx_id.into(),
                    0
                ))
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_redeem_fixed_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let supply_limit = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Fixed(supply_limit));

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..supply_limit.into_atoms()));
        let amount_to_mint_over_limit = (supply_limit + Amount::from_atoms(1)).unwrap();

        let amount_to_redeem = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));
        let amount_to_redeem_over_limit = (amount_to_mint + Amount::from_atoms(1)).unwrap();

        // Mint over the limit
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, amount_to_mint_over_limit),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                        token_id,
                        amount_to_mint_over_limit,
                        Destination::AnyoneCanSpend,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::MintExceedsSupplyLimit(
                        amount_to_mint_over_limit,
                        supply_limit,
                        token_id
                    )
                )
            ))
        );

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                token_id,
                amount_to_mint,
                Destination::AnyoneCanSpend,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Redeem more than minted
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, amount_to_redeem_over_limit),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::RedeemTokens(
                        token_id,
                        amount_to_redeem_over_limit,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_redeem_over_limit,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::NotEnoughCirculatingSupplyToRedeem(
                        amount_to_mint,
                        amount_to_redeem_over_limit,
                        token_id
                    )
                )
            ))
        );

        // Redeem some tokens
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, amount_to_redeem),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::RedeemTokens(
                        token_id,
                        amount_to_redeem,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_redeem,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_redeem).unwrap())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unlimited_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                token_id,
                amount_to_mint,
                Destination::AnyoneCanSpend,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_lockable_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_redeem = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_supply_change_fee * 5).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                token_id,
                amount_to_mint,
                Destination::AnyoneCanSpend,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(!data.is_locked()),
        };

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(nonce, AccountSpending::TokenSupply(token_id, Amount::ZERO)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                token_id,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(lock_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_locked()),
        };

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Try to mint some tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                        token_id,
                        amount_to_mint,
                        Destination::AnyoneCanSpend,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::CannotMintFromLockedSupply(token_id)
                )
            ))
        );

        // Try to redeem some tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, amount_to_redeem),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::RedeemTokens(
                        token_id,
                        amount_to_redeem,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_redeem,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::CannotRedeemFromLockedSupply(token_id)
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), TokenTotalSupply::Unlimited)]
#[trace]
#[case(Seed::from_entropy(), TokenTotalSupply::Fixed(Amount::from_atoms(1)))]
fn try_lock_not_lockable_supply(#[case] seed: Seed, #[case] supply: TokenTotalSupply) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(&mut rng, &mut tf, supply);

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenSupply(token_id, Amount::ZERO),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                        token_id,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::CannotLockNotLockableSupply(token_id)
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_lock_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(nonce, AccountSpending::TokenSupply(token_id, Amount::ZERO)),
                InputWitness::NoSignature(None),
            )
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                token_id,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(lock_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_locked()),
        };

        // Try lock again
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenSupply(token_id, Amount::ZERO),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                        token_id,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::SupplyIsAlreadyLocked(token_id)
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn supply_change_fees(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let low_fee = (tf.chainstate.get_chain_config().token_min_supply_change_fee()
            - Amount::from_atoms(1))
        .unwrap();

        let some_amount = Amount::from_atoms(rng.gen_range(100..100_000));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        // Try mint with insufficient fee
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenSupply(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                        token_id,
                        some_amount,
                        Destination::AnyoneCanSpend,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(low_fee)))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));

        // Try redeem with insufficient fee
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenSupply(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Tokens(TokenOutput::RedeemTokens(
                        token_id,
                        some_amount,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(low_fee)))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(token_id, some_amount)))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));

        // Try lock with insufficient fee
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenSupply(token_id, Amount::ZERO),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
                    .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                        token_id,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(low_fee)))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::InsufficientTokenFees(_, _)
                ))
            ))
        ));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_and_redeem_outputs_cannot_be_spent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_redeem = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_supply_change_fee * 5).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                token_id,
                amount_to_mint,
                Destination::AnyoneCanSpend,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Redeem some tokens
        let redeem_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenSupply(token_id, amount_to_redeem),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Tokens(TokenOutput::RedeemTokens(
                token_id,
                amount_to_redeem,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_redeem,
            )))
            .build();
        let redeem_tx_id = redeem_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(redeem_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(nonce, AccountSpending::TokenSupply(token_id, Amount::ZERO)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(redeem_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Tokens(TokenOutput::LockCirculatingSupply(
                token_id,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(lock_tx).build_and_process().unwrap();

        // Try to spend redeem output
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(redeem_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(common::chain::UtxoOutPoint::new(
                    redeem_tx_id.into(),
                    1
                ))
            ))
        );

        // Try to spend lock output
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(common::chain::UtxoOutPoint::new(
                    lock_tx_id.into(),
                    0
                ))
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_mint_tokens_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_overspend = (amount_to_mint + Amount::from_atoms(1)).unwrap();

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Tokens(TokenOutput::MintTokens(
                token_id,
                amount_to_mint,
                Destination::AnyoneCanSpend,
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();

        // Check result
        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Try to overspend minted amount
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_overspend),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(amount_to_mint, amount_to_overspend)
            ))
        );

        // Try to spend proper amount
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.best_block_id();

        let amount_to_mint_1 = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_mint_2 = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        // create another block with 2 outputs to use them on tokens issuance and get 2 distinct token ids
        let tx_a = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_supply_change_fee * 100).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_supply_change_fee * 100).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_a_id = tx_a.transaction().get_id();
        tf.make_block_builder().add_transaction(tx_a).build_and_process().unwrap();
        let block_a_id = tf.best_block_id();

        // Create block `b` with token1 issuance
        let (token_id_1, block_b_id, block_b_change_utxo) = issue_token_from_block(
            &mut tf,
            block_a_id,
            UtxoOutPoint::new(tx_a_id.into(), 0),
            make_issuance(&mut rng, TokenTotalSupply::Unlimited),
        );
        assert_eq!(tf.best_block_id(), block_b_id);

        // Create block `c` with token1 minting
        let block_c_id = mint_tokens_in_block(
            &mut tf,
            block_b_id.into(),
            block_b_change_utxo,
            token_id_1,
            amount_to_mint_1,
        );
        assert_eq!(tf.best_block_id(), block_c_id);

        // Create block `d` with another token issuance
        let issuance_token_2 = make_issuance(&mut rng, TokenTotalSupply::Lockable);
        let (token_id_2, block_d_id, block_d_change_utxo) = issue_token_from_block(
            &mut tf,
            block_a_id,
            UtxoOutPoint::new(tx_a_id.into(), 1),
            issuance_token_2.clone(),
        );
        // No reorg
        assert_eq!(tf.best_block_id(), block_c_id);
        println!("token1: {}, token2: {}", token_id_1, token_id_2);

        // Mint some tokens
        let block_e_id = mint_tokens_in_block(
            &mut tf,
            block_d_id.into(),
            block_d_change_utxo,
            token_id_2,
            amount_to_mint_2,
        );
        // No reorg
        assert_eq!(tf.best_block_id(), block_c_id);

        // Add empty block to trigger the reorg
        let block_f = tf.make_block_builder().with_parent(block_e_id.into()).build();
        let block_f_id = block_f.get_id();
        tf.process_block(block_f, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), block_f_id);

        // Check the storage
        assert!(
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id_1)
                .unwrap()
                .is_none()
        );
        assert!(
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id_1)
                .unwrap()
                .is_none()
        );

        assert_eq!(
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id_2).unwrap(),
            Some(tokens_accounting::TokenData::FungibleToken(
                issuance_token_2.into()
            ))
        );
        assert_eq!(
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id_2).unwrap(),
            Some(amount_to_mint_2)
        );
    });
}
