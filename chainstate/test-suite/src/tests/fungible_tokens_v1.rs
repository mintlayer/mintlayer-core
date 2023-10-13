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
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{make_token_id, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        AccountNonce, AccountSpending, AccountType, Block, Destination, GenBlock, OutPointSourceId,
        TokenOutput, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{signed_amount::SignedAmount, Amount, Id, Idable},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    decompose_value, gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string,
};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::error::TokenIssuanceError;
use tx_verifier::transaction_verifier::signature_destination_getter::SignatureDestinationGetterError;

fn make_issuance(rng: &mut impl Rng, supply: TokenTotalSupply) -> TokenIssuance {
    TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: random_string(rng, 1..5).as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: random_string(rng, 1..1024).as_bytes().to_vec(),
        total_supply: supply,
        reissuance_controller: Destination::AnyoneCanSpend,
    })
}

fn issue_token_from_block(
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_input_outpoint: UtxoOutPoint,
    issuance: TokenIssuance,
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
        .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
            Box::new(issuance.clone()),
        )))
        .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
        .build();
    let token_id = make_token_id(tx.transaction().inputs()).unwrap();
    let tx_id = tx.transaction().get_id();
    let block = tf.make_block_builder().add_transaction(tx).with_parent(parent_block_id).build();
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();

    (token_id, block_id, UtxoOutPoint::new(tx_id.into(), 0))
}

// Returns created token id and outpoint with change
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
    produce_change: bool,
) -> (Id<Block>, Id<Transaction>) {
    let token_min_supply_change_fee =
        tf.chainstate.get_chain_config().token_min_supply_change_fee();

    let nonce = BlockchainStorageRead::get_account_nonce_count(
        &tf.storage,
        AccountType::TokenSupply(token_id),
    )
    .unwrap()
    .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

    let tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_account(
                nonce,
                AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
            ),
            InputWitness::NoSignature(None),
        )
        .add_input(
            utxo_to_pay_fee.clone().into(),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Burn(OutputValue::Coin(
            token_min_supply_change_fee,
        )))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, amount_to_mint),
            Destination::AnyoneCanSpend,
        ));

    let tx_builder = if produce_change {
        let fee_utxo_coins = chainstate_test_framework::get_output_value(
            tf.chainstate.utxo(&utxo_to_pay_fee).unwrap().unwrap().output(),
        )
        .unwrap()
        .coin_amount()
        .unwrap();

        tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin((fee_utxo_coins - token_min_supply_change_fee).unwrap()),
            Destination::AnyoneCanSpend,
        ))
    } else {
        tx_builder
    };

    let tx = tx_builder.build();
    let tx_id = tx.transaction().get_id();

    let block = tf.make_block_builder().add_transaction(tx).with_parent(parent_block_id).build();
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();

    (block_id, tx_id)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let token_max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let token_max_dec_count = tf.chainstate.get_chain_config().token_max_dec_count();
        let token_max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        let mut process_block_with_issuance = |issuance: TokenIssuance| {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(genesis_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                    Box::new(issuance),
                )))
                .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                .build();
            let tx_id = tx.transaction().get_id();
            let block = tf.make_block_builder().add_transaction(tx).build();
            let block_id = block.get_id();
            let result = tf.process_block(block, BlockSource::Local);
            (result, tx_id, block_id)
        };

        // Ticker is too long
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 10..u16::MAX as usize).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
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
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
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
                let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                    token_ticker,
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
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

            let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: decimals_count_to_use,
                metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
                total_supply: TokenTotalSupply::Unlimited,
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

            let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_string(&mut rng, uri_len_range_to_use).as_bytes().to_vec(),
                total_supply: TokenTotalSupply::Unlimited,
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
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
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
        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                Box::new(issuance.clone()),
            )))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let token_id = make_token_id(tx.transaction().inputs()).unwrap();
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

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                        Box::new(issuance.clone()),
                    )))
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

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                Box::new(issuance.clone()),
            )))
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
                    .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                        Box::new(issuance.clone()),
                    )))
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
fn mint_unmint_fixed_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let total_supply = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Fixed(total_supply));

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..total_supply.into_atoms()));
        let amount_to_mint_over_limit = (total_supply + Amount::from_atoms(1)).unwrap();

        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));
        let amount_to_unmint_over_limit = (amount_to_mint + Amount::from_atoms(1)).unwrap();

        // Mint over the limit
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenTotalSupply(token_id, amount_to_mint_over_limit),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint_over_limit),
                        Destination::AnyoneCanSpend,
                    ))
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
                        total_supply,
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
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
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
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
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

        // Unmint more than minted
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint_over_limit,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(
                    amount_to_mint,
                    amount_to_unmint_over_limit,
                )
            ))
        );

        // Unmint some tokens
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_unmint).unwrap())
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

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..i128::MAX as u128));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
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
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
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
fn mint_from_wrong_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let mut mint_from_account = |account_spending| {
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::from_account(AccountNonce::new(0), account_spending),
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
                        .add_output(TxOutput::Transfer(
                            OutputValue::TokenV1(token_id, amount_to_mint),
                            Destination::AnyoneCanSpend,
                        ))
                        .add_output(TxOutput::Burn(OutputValue::Coin(
                            token_min_supply_change_fee,
                        )))
                        .build(),
                )
                .build_and_process()
        };

        let result = mint_from_account(AccountSpending::TokenCirculatingSupply(token_id));
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(Amount::ZERO, amount_to_mint)
            ))
        );

        let result = mint_from_account(AccountSpending::TokenSupplyLock(token_id));
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(Amount::ZERO, amount_to_mint)
            ))
        );

        mint_from_account(AccountSpending::TokenTotalSupply(token_id, amount_to_mint)).unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_to_print_money_on_mint(#[case] seed: Seed) {
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

        // Mint but skip account input
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(token_min_issuance_fee),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(Amount::ZERO, amount_to_mint)
            ))
        );

        // Mint but input amount is lees then output
        let amount_to_mint_input = (amount_to_mint - Amount::from_atoms(1)).unwrap();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenTotalSupply(token_id, amount_to_mint_input),
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
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(amount_to_mint_input, amount_to_mint)
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_from_total_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1_000_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // Unminting from TokenTotalSupply is not an error because it's basically minting and burning at once
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenTotalSupply(token_id, amount_to_unmint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let circulating_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(
            circulating_supply,
            Some((amount_to_mint + amount_to_unmint).unwrap())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_from_lock_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // Unminting from TokenSupplyLock is not an error because it's basically just locking and burning at once
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(nonce, AccountSpending::TokenSupplyLock(token_id)),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let circulating_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(circulating_supply, Some(amount_to_mint));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_zero_tokens_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // Try to skip burning tokens at all
        // In this case no tokens are unminted
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burning_less_then_input_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_burn = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // it's ok to burn less tokens than the input has. In this case only the burned amount will be unminted
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_burn,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_burn).unwrap())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_to_burn_less_by_providing_smaller_input_utxo(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // split tokens in 2 utxo so that one can be used to try to cheat burning rules
        let tx_transfer_tokens = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(
                    token_id,
                    (amount_to_unmint - Amount::from_atoms(1)).unwrap(),
                ),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_transfer_tokens_id = tx_transfer_tokens.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_transfer_tokens)
            .build_and_process()
            .unwrap();

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // The outputs contain proper amount of burn tokens
        // But inputs use a utxo that is less by 1 and thus should fail to satisfy constraints
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_transfer_tokens_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(
                    (amount_to_unmint - Amount::from_atoms(1)).unwrap(),
                    amount_to_unmint
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_using_multiple_burn_utxos(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let split_outputs = decompose_value(&mut rng, amount_to_unmint.into_atoms())
            .iter()
            .map(|value| {
                TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(*value)),
                    Destination::AnyoneCanSpend,
                )
            })
            .collect::<Vec<_>>();
        let number_of_tokens_utxos = split_outputs.len();

        // split tokens into random number of utxos
        let tx_split_tokens = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .with_outputs(split_outputs)
            .build();
        let tx_split_tokens_id = tx_split_tokens.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_split_tokens)
            .build_and_process()
            .unwrap();

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage,
            AccountType::TokenSupply(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // The outputs contain proper amount of burn tokens
        // But inputs use a utxo that is less by 1 and thus should fail to satisfy constraints
        let inputs_to_unmint = (0..number_of_tokens_utxos)
            .map(|i| TxInput::from_utxo(tx_split_tokens_id.into(), i as u32))
            .collect::<Vec<_>>();
        let burn_outputs = decompose_value(&mut rng, amount_to_unmint.into_atoms())
            .iter()
            .map(|value| TxOutput::Burn(OutputValue::TokenV1(token_id, Amount::from_atoms(*value))))
            .collect::<Vec<_>>();
        let witnesses = vec![InputWitness::NoSignature(None); inputs_to_unmint.len()];

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .with_inputs(inputs_to_unmint)
                    .with_witnesses(witnesses)
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .with_outputs(burn_outputs)
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .build(),
            )
            .build_and_process()
            .unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_unmint).unwrap())
        );
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
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
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
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
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
                TxInput::from_account(nonce, AccountSpending::TokenSupplyLock(token_id)),
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
                            AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
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

        // Try to unmint some tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            nonce,
                            AccountSpending::TokenCirculatingSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::Coin(
                        token_min_supply_change_fee,
                    )))
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::CannotUnmintFromLockedSupply(token_id)
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
                            AccountSpending::TokenSupplyLock(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
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
                TxInput::from_account(nonce, AccountSpending::TokenSupplyLock(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
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
                        TxInput::from_account(nonce, AccountSpending::TokenSupplyLock(token_id)),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
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
                            AccountSpending::TokenTotalSupply(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, some_amount),
                        Destination::AnyoneCanSpend,
                    ))
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

        // Try unmint with insufficient fee
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(0),
                            AccountSpending::TokenTotalSupply(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
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
                            AccountSpending::TokenSupplyLock(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
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
fn lock_and_unmint_outputs_cannot_be_spent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Lockable);

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
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
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
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

        // Unmint some tokens
        let unmint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    nonce,
                    AccountSpending::TokenTotalSupply(token_id, amount_to_unmint),
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
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_unmint,
            )))
            .build();
        let unmint_tx_id = unmint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(unmint_tx).build_and_process().unwrap();
        nonce = nonce.increment().unwrap();

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(nonce, AccountSpending::TokenSupplyLock(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(unmint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(lock_tx).build_and_process().unwrap();

        // Try to spend unmint output
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(unmint_tx_id.into(), 1),
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
                    unmint_tx_id.into(),
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
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
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
fn issue_and_mint_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_source_id.clone(), 0)]).unwrap();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                Box::new(issuance.clone()),
            )))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let token_id = make_token_id(tx.transaction().inputs()).unwrap();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::DestinationRetrievalError(
                    SignatureDestinationGetterError::TokenDataNotFound(token_id)
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_mint_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_source_id.clone(), 0)]).unwrap();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let tx_issuance = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                Box::new(issuance.clone()),
            )))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_issuance_id = tx_issuance.transaction().get_id();

        let tx_minting = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_issuance_id.into(), 2),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();

        tf.make_block_builder()
            .with_transactions(vec![tx_issuance, tx_minting])
            .build_and_process()
            .unwrap();

        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
        let expected_token_data = tokens_accounting::TokenData::FungibleToken(issuance.into());
        assert_eq!(actual_token_data, Some(expected_token_data));

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
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
        let (block_c_id, _) = mint_tokens_in_block(
            &mut tf,
            block_b_id.into(),
            block_b_change_utxo,
            token_id_1,
            amount_to_mint_1,
            false,
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
        let (block_e_id, _) = mint_tokens_in_block(
            &mut tf,
            block_d_id.into(),
            block_d_change_utxo,
            token_id_2,
            amount_to_mint_2,
            false,
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
