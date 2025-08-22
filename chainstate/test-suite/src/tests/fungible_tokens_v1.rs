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

use std::{borrow::Cow, collections::BTreeMap};

use rstest::rstest;

use chainstate::{
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, IOPolicyError, TokensError,
};
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_test_framework::{
    helpers::{issue_token_from_block, mint_tokens_in_block},
    TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        make_token_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::input_commitments::SighashInputCommitment,
            DestinationSigError,
        },
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, TokenId, TokenIssuance, TokenIssuanceV1,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountType, Block, ChainstateUpgradeBuilder, Destination,
        GenBlock, OrderData, OutPointSourceId, SignedTransaction, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{amount::SignedAmount, Amount, BlockHeight, CoinOrTokenId, Id, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::{CryptoRng, Rng};
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string, split_value,
};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::{
    error::{InputCheckError, ScriptError, TimelockError},
    transaction_verifier::error::TokenIssuanceError,
    CheckTransactionError,
};

fn make_issuance(
    rng: &mut impl Rng,
    supply: TokenTotalSupply,
    freezable: IsTokenFreezable,
) -> TokenIssuance {
    TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: random_ascii_alphanumeric_string(rng, 1..5).as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: random_ascii_alphanumeric_string(rng, 1..1024).as_bytes().to_vec(),
        total_supply: supply,
        authority: Destination::AnyoneCanSpend,
        is_freezable: freezable,
    })
}

// Returns created token id and outpoint with change
fn issue_token_from_genesis(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    supply: TokenTotalSupply,
    freezable: IsTokenFreezable,
) -> (TokenId, Id<Block>, UtxoOutPoint) {
    let utxo_input_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);
    let issuance = make_issuance(rng, supply, freezable);
    issue_token_from_block(
        rng,
        tf,
        tf.genesis().get_id().into(),
        utxo_input_outpoint,
        issuance,
    )
}

fn unmint_tokens_in_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    token_id: TokenId,
    utxo_to_burn_tokens: UtxoOutPoint,
    utxo_to_pay_fee: UtxoOutPoint,
    amount_to_unmint: Amount,
) -> (Id<Block>, Id<Transaction>) {
    let token_supply_change_fee =
        tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

    let nonce = BlockchainStorageRead::get_account_nonce_count(
        &tf.storage.transaction_ro().unwrap(),
        AccountType::Token(token_id),
    )
    .unwrap()
    .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

    let fee_input_utxo_coins =
        chainstate_test_framework::get_output_value(tf.utxo(&utxo_to_pay_fee).output())
            .unwrap()
            .coin_amount()
            .unwrap();

    let tokens_input_utxo_amount =
        match chainstate_test_framework::get_output_value(tf.utxo(&utxo_to_burn_tokens).output())
            .unwrap()
        {
            OutputValue::Coin(_) | OutputValue::TokenV0(_) => {
                panic!("Invalid input to burn tokens")
            }
            OutputValue::TokenV1(_, amount) => amount,
        };

    let tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
            InputWitness::NoSignature(None),
        )
        .add_input(
            utxo_to_burn_tokens.clone().into(),
            InputWitness::NoSignature(None),
        )
        .add_input(
            utxo_to_pay_fee.clone().into(),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Burn(OutputValue::TokenV1(
            token_id,
            amount_to_unmint,
        )))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(
                token_id,
                (tokens_input_utxo_amount - amount_to_unmint).unwrap(),
            ),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((fee_input_utxo_coins - token_supply_change_fee).unwrap()),
            Destination::AnyoneCanSpend,
        ));

    let tx = tx_builder.build();
    let tx_id = tx.transaction().get_id();

    let block = tf
        .make_block_builder()
        .add_transaction(tx)
        .with_parent(parent_block_id)
        .build(rng);
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
        let mut rng2 = make_seedable_rng(rng.gen::<Seed>());
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        let token_max_dec_count = tf.chainstate.get_chain_config().token_max_dec_count();
        let token_max_uri_len = tf.chainstate.get_chain_config().token_max_uri_len();

        let mut process_block_with_issuance = |issuance: TokenIssuance| {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(genesis_source_id.clone(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
                .build();
            let tx_id = tx.transaction().get_id();
            let block = tf.make_block_builder().add_transaction(tx).build(&mut rng2);
            let block_id = block.get_id();
            let result = tf.process_block(block, BlockSource::Local);
            (result, tx_id, block_id)
        };

        // Ticker is too long
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(
                &mut rng,
                (token_max_ticker_len + 1)..u16::MAX as usize,
            )
            .as_bytes()
            .to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });
        let (result, tx_id, _) = process_block_with_issuance(issuance);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidTickerLength,
                            tx_id,
                        ))
                    )
                )
            ))
        );

        // Ticker doesn't exist
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: b"".to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });
        let (result, tx_id, _) = process_block_with_issuance(issuance);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorInvalidTickerLength,
                            tx_id,
                        ))
                    )
                )
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
                    metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024)
                        .as_bytes()
                        .to_vec(),
                    total_supply: TokenTotalSupply::Unlimited,
                    authority: Destination::AnyoneCanSpend,
                    is_freezable: IsTokenFreezable::No,
                });
                let (result, tx_id, _) = process_block_with_issuance(issuance);

                assert_eq!(
                    result.unwrap_err(),
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
            }
        }

        // Too many decimals
        {
            let decimals_count_to_use = token_max_dec_count + 1;

            let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: decimals_count_to_use,
                metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024)
                    .as_bytes()
                    .to_vec(),
                total_supply: TokenTotalSupply::Unlimited,
                authority: Destination::AnyoneCanSpend,
                is_freezable: IsTokenFreezable::No,
            });
            let (result, tx_id, _) = process_block_with_issuance(issuance);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorTooManyDecimals,
                                tx_id,
                            ))
                        )
                    )
                ))
            );
        }

        // URI is too long
        {
            let uri_len_range_to_use = (token_max_uri_len + 1)..u16::MAX as usize;

            let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_ascii_alphanumeric_string(&mut rng, uri_len_range_to_use)
                    .as_bytes()
                    .to_vec(),
                total_supply: TokenTotalSupply::Unlimited,
                authority: Destination::AnyoneCanSpend,
                is_freezable: IsTokenFreezable::No,
            });
            let (result, tx_id, _) = process_block_with_issuance(issuance);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    CheckBlockError::CheckTransactionFailed(
                        CheckBlockTransactionsError::CheckTransactionError(
                            CheckTransactionError::TokensError(TokensError::IssueError(
                                TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                                tx_id,
                            ))
                        )
                    )
                ))
            );
        }

        // URI contain non alpha-numeric char
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://💖🚁🌭.🦠🚀🚖🚧".as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });
        let (result, tx_id, _) = process_block_with_issuance(issuance);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(TokensError::IssueError(
                            TokenIssuanceError::IssueErrorIncorrectMetadataURI,
                            tx_id,
                        ))
                    )
                )
            ))
        );

        // Valid case
        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            tf.next_block_height(),
            tx.inputs(),
        )
        .unwrap();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let expected_token_data = tokens_accounting::TokenData::FungibleToken(issuance.into());
        assert_eq!(actual_token_data, Some(expected_token_data));

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, None);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_twice_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let issuance1 = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });
        let issuance2 = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance1.clone())))
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance2.clone())))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(
                            TokensError::MultipleTokenIssuanceInTransaction(tx_id,)
                        )
                    )
                )
            ))
        );
    });
}

// Create a tx with 2 output: one is less than required fee and one with equal amount.
// Try issuing a token by using smaller output for fee; check that's an error.
// Then use second output and check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_not_enough_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_issuance_fee - Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::Coin
                    ),
                    tx_id.into()
                )
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Check that an output produced from issuing a token cannot be spent
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_output_cannot_be_spent(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();
        let tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::ZERO),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

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

// Issue a token with fixed supply.
// Mint tokens over total supply, check an error.
// Mint tokens in supply range, check storage.
// Unmint more tokens that been minter, check an error.
// Unmint tokens in minter range, check storage.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unmint_fixed_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let total_supply = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Fixed(total_supply),
            IsTokenFreezable::No,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..total_supply.into_atoms()));
        let amount_to_mint_over_limit = (total_supply + Amount::from_atoms(1)).unwrap();

        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));
        let amount_to_unmint_over_limit = (amount_to_mint + Amount::from_atoms(1)).unwrap();

        // Mint over the limit

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    nonce,
                    AccountCommand::MintTokens(token_id, amount_to_mint_over_limit),
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
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::MintExceedsSupplyLimit(
                            amount_to_mint_over_limit,
                            total_supply,
                            token_id
                        )
                    ),
                    tx_id.into()
                )
            ))
        );

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::MintTokens(token_id, amount_to_mint)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Unmint more than minted
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
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
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_unmint_over_limit,
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Unmint some tokens
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
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
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_unmint).unwrap())
        );
    });
}

// Issue a token.
// Use 2 mint inputs in the same tx.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_twice_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));

        // Mint tokens
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, (amount_to_mint * 2).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        // Check result
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    tx_id.into()
                )
            ))
        );
    });
}

// Issue and mint some tokens.
// Try to use 2 unmint inputs in the same tx.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_unmint_twice_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Unmint tokens twice
        let unmint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(AccountNonce::new(1), AccountCommand::UnmintTokens(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(AccountNonce::new(2), AccountCommand::UnmintTokens(token_id)),
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
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_mint,
            )))
            .build();
        let unmint_tx_id = unmint_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(unmint_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    unmint_tx_id.into()
                )
            ))
        );
    });
}

// Issue 2 tokens and mint some.
// Try to use 2 unmint inputs in the same tx for different tokens.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_two_tokens_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut rng2 = make_seedable_rng(rng.gen::<Seed>());
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id_1, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (token_id_2, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            make_issuance(&mut rng2, TokenTotalSupply::Unlimited, IsTokenFreezable::No),
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_1_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id_1,
            amount_to_mint,
            true,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_2_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            UtxoOutPoint::new(mint_tx_1_id.into(), 1),
            token_id_2,
            amount_to_mint,
            true,
        );

        assert_eq!(
            TokensAccountingStorageRead::get_circulating_supply(
                &tf.storage.transaction_ro().unwrap(),
                &token_id_1
            )
            .unwrap(),
            Some(amount_to_mint)
        );
        assert_eq!(
            TokensAccountingStorageRead::get_circulating_supply(
                &tf.storage.transaction_ro().unwrap(),
                &token_id_2
            )
            .unwrap(),
            Some(amount_to_mint)
        );

        // Unmint both tokens tokens same tx
        let unmint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnmintTokens(token_id_1),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnmintTokens(token_id_2),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_1_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_2_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_2_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id_1,
                amount_to_mint,
            )))
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id_2,
                amount_to_mint,
            )))
            .build();
        let unmint_tx_id = unmint_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(unmint_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    unmint_tx_id.into()
                )
            ))
        );
    });
}

// Issue a token with random fixed supply.
// Mint all tokens up to the total supply.
// Try mint 1 more tokens and check an error.
// Unmint 1 token.
// Try mint 2 tokens and check an error.
// Unmint N tokens.
// Try mint N+1 tokens and check an error.
// Mint N tokens and check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unmint_fixed_supply_repeatedly(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let total_supply = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Fixed(total_supply),
            IsTokenFreezable::No,
        );

        // Mint all the tokens up to the total supply
        let best_block_id = tf.best_block_id();
        let (_, mint_total_supply_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            total_supply,
            true,
        );

        // Mint 1 tokens over the limit
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::MintTokens(token_id, Amount::from_atoms(1)),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_total_supply_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::MintExceedsSupplyLimit(
                            Amount::from_atoms(1),
                            total_supply,
                            token_id
                        )
                    ),
                    tx_id.into()
                )
            ))
        );

        // Unmint 1 token
        let best_block_id = tf.best_block_id();
        let (_, unmint_1_token_tx_id) = unmint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            token_id,
            UtxoOutPoint::new(mint_total_supply_tx_id.into(), 0),
            UtxoOutPoint::new(mint_total_supply_tx_id.into(), 1),
            Amount::from_atoms(1),
        );

        // Try mint 2 tokens which is still over the limit

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(2),
                    AccountCommand::MintTokens(token_id, Amount::from_atoms(2)),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(unmint_1_token_tx_id.into(), 2),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::MintExceedsSupplyLimit(
                            Amount::from_atoms(2),
                            total_supply,
                            token_id
                        )
                    ),
                    tx_id.into()
                )
            ))
        );

        // Unmint n tokens
        // Note: -1 because 1 was unminted previously
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..total_supply.into_atoms() - 1));
        let best_block_id = tf.best_block_id();
        let (_, unmint_n_tokens_tx_id) = unmint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            token_id,
            UtxoOutPoint::new(unmint_1_token_tx_id.into(), 1),
            UtxoOutPoint::new(unmint_1_token_tx_id.into(), 2),
            amount_to_unmint,
        );

        // Try mint n+1 tokens which is still over the limit
        // Note: +2 below because 1 was unminted previously and 1 to get over the limit
        let amount_to_unmint_plus_1 = (amount_to_unmint + Amount::from_atoms(2)).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(3),
                    AccountCommand::MintTokens(token_id, amount_to_unmint_plus_1),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(unmint_n_tokens_tx_id.into(), 2),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_unmint_plus_1),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::MintExceedsSupplyLimit(
                            amount_to_unmint_plus_1,
                            total_supply,
                            token_id
                        )
                    ),
                    tx_id.into()
                )
            ))
        );

        // Mint exactly the amount that was totally unminted
        let amount_to_mint = (amount_to_unmint + Amount::from_atoms(1)).unwrap();
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(3),
                            AccountCommand::MintTokens(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unmint_n_tokens_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        assert_eq!(
            tf.storage
                .transaction_ro()
                .unwrap()
                .get_circulating_supply(&token_id)
                .unwrap()
                .unwrap(),
            total_supply
        );
    });
}

// Check that if supply is unlimited up to i128::MAX tokens can be minted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unlimited_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..=i128::MAX as u128));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        // Mint more than i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, Amount::from_atoms(i128::MAX as u128 + 1)),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(mint_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorToSignedFailed
                        )
                    ),
                    mint_tx_id.into()
                )
            ))
        );

        // Mint tokens <= i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
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
            .build();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
    });
}

// Issue and mint maximum possible tokens for Unlimited supply.
// Try to mint 1 more and check an error.
// Try to mint random number and check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unlimited_supply_max(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let max_amount_to_mint = Amount::from_atoms(i128::MAX as u128);
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        // Mint tokens i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, max_amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, max_amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(max_amount_to_mint));

        {
            // Try mint one more over i128::MAX
            let mint_tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_command(
                        AccountNonce::new(1),
                        AccountCommand::MintTokens(token_id, Amount::from_atoms(1)),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    TxInput::from_utxo(mint_tx_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                    Destination::AnyoneCanSpend,
                ))
                .build();
            let mint_tx_id = mint_tx.transaction().get_id();
            let result =
                tf.make_block_builder().add_transaction(mint_tx).build_and_process(&mut rng);

            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::ConstrainedValueAccumulatorError(
                        constraints_value_accumulator::Error::TokensAccountingError(
                            tokens_accounting::Error::AccountingError(
                                accounting::Error::ArithmeticErrorDeltaAdditionFailed
                            )
                        ),
                        mint_tx_id.into()
                    )
                ))
            );
        }

        // Try mint random number over i128::MAX
        let random_amount = Amount::from_atoms(rng.gen_range(0..i128::MAX as u128));
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::MintTokens(token_id, random_amount),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, random_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(mint_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorDeltaAdditionFailed
                        )
                    ),
                    mint_tx_id.into()
                )
            ))
        );
    });
}

// Issue a token and try to mint from different account types.
// Mint from TokenCirculatingSupply and check an error.
// Mint from TokenLockSupply and check an error.
// Mint from TokenTotalSupply and check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_from_wrong_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let mut mint_from_account = |account_spending| {
            tf.make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::from_command(AccountNonce::new(0), account_spending),
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
                        .build(),
                )
                .build_and_process(&mut rng)
        };

        let result = mint_from_account(AccountCommand::UnmintTokens(token_id));
        assert!(matches!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(_)
                    ),
                    _
                )
            ))
        ));

        let result = mint_from_account(AccountCommand::LockTokenSupply(token_id));
        assert!(matches!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(_)
                    ),
                    _
                )
            ))
        ));

        mint_from_account(AccountCommand::MintTokens(token_id, amount_to_mint)).unwrap();
    });
}

// Issue a token and try to print some tokens:
// Mint some tokens but skip account input, check an error;
// Mint some tokens but provide les in an account input than in the output, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_to_print_money_on_mint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        // Mint but skip account input
        let tx = TransactionBuilder::new()
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Mint but input amount is lees then output
        let amount_to_mint_input = (amount_to_mint - Amount::from_atoms(1)).unwrap();
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint_input),
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
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Issue a token, mint some and try to burn tokens and spend from total supply account.
// Check that it's not an error an that the tokens actually are minted
// and burned without unminting.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_from_total_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1_000_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // Spending from TokenTotalSupply and burning is not an error
        // because it's basically minting new tokens without outputs (that can be scooped by miner)
        // and burning the tokens from inputs without unminting.
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::MintTokens(token_id, amount_to_unmint),
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
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let circulating_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(
            circulating_supply,
            Some((amount_to_mint + amount_to_unmint).unwrap())
        );
    });
}

// Issue a token, mint some and try to burn tokens and spend from lock supply account.
// Check that it's not an error and that the supply is actually locked
// and tokens are burned without unminting.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_from_lock_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // Unminting from TokenSupplyLock is not an error because it's basically just locking and burning at once
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::LockTokenSupply(token_id),
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
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let circulating_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(circulating_supply, Some(amount_to_mint));

        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_locked()),
        };
    });
}

// Issue a token and mint some.
// Unmint from account but skip burning tokens at all.
// Check that no tokens were unminted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_zero_tokens_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage.transaction_ro().unwrap(),
            AccountType::Token(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // Try to skip burning tokens at all
        // In this case no tokens are unminted
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
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
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
    });
}

// Issue and mint some tokens.
// On unmint the number of burned tokens in output is less then in the input utxo.
// Check that exactly burned amount was unminted (not the amount from input utxo)
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_less_than_input_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_burn = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage.transaction_ro().unwrap(),
            AccountType::Token(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // it's ok to burn less tokens than the input has. In this case only the burned amount will be unminted
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
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
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_burn,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_burn).unwrap())
        );
    });
}

// Issue and mint some tokens.
// On unmint provide a utxo that has less tokens that burned output.
// Check that it's an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_less_by_providing_smaller_input_utxo(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
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
                TxInput::from_utxo(mint_tx_id.into(), 0),
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
            .build_and_process(&mut rng)
            .unwrap();

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage.transaction_ro().unwrap(),
            AccountType::Token(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        // The outputs contain proper amount of burn tokens
        // But inputs use a utxo that is less by 1 and thus should fail to satisfy constraints
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_transfer_tokens_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_unmint,
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Issue and mint some tokens.
// Unmint by providing multiple input utxos with tokens and burning them in multiple outputs.
// Check that the total tokens taken from circulation is a sum of burned outputs.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_using_multiple_burn_utxos(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        let split_outputs = split_value(&mut rng, amount_to_unmint.into_atoms())
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
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .with_outputs(split_outputs)
            .build();
        let tx_split_tokens_id = tx_split_tokens.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_split_tokens)
            .build_and_process(&mut rng)
            .unwrap();

        let nonce = BlockchainStorageRead::get_account_nonce_count(
            &tf.storage.transaction_ro().unwrap(),
            AccountType::Token(token_id),
        )
        .unwrap()
        .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

        let inputs_to_unmint = (0..number_of_tokens_utxos)
            .map(|i| TxInput::from_utxo(tx_split_tokens_id.into(), i as u32))
            .collect::<Vec<_>>();
        // Create random number of outputs that burn tokens
        let burn_outputs = split_value(&mut rng, amount_to_unmint.into_atoms())
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
                        TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .with_outputs(burn_outputs)
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(
            actual_supply,
            Some((amount_to_mint - amount_to_unmint).unwrap())
        );
    });
}

// Issue and mint some tokens.
// Lock the supply.
// Check that after that no more tokens can be minted or unminted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_lockable_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::MintTokens(token_id, amount_to_mint)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 5).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(!data.is_locked()),
        };

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::LockTokenSupply(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(lock_tx)
            .build_and_process(&mut rng)
            .unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_locked()),
        };

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Try to mint some tokens
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::MintTokens(token_id, amount_to_mint)),
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
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::CannotMintFromLockedSupply(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Try to unmint some tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
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
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_unmint,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng);

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

// Issue a token.
// Check that Unlimited and Fixed supplies cannot be locked.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), TokenTotalSupply::Unlimited)]
#[trace]
#[case(Seed::from_entropy(), TokenTotalSupply::Fixed(Amount::from_atoms(1)))]
fn try_lock_not_lockable_supply(#[case] seed: Seed, #[case] supply: TokenTotalSupply) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, supply, IsTokenFreezable::No);

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::LockTokenSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
                    .build(),
            )
            .build_and_process(&mut rng);

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

// Issue a token and lock the supply.
// Try to lock once more and check the error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_lock_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut nonce = AccountNonce::new(0);

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        // Lock the supply
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::LockTokenSupply(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(lock_tx)
            .build_and_process(&mut rng)
            .unwrap();
        nonce = nonce.increment().unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_locked()),
        };

        // Try lock again
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(nonce, AccountCommand::LockTokenSupply(token_id)),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(lock_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng);

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

// Issue a token.
// Try to use 2 lock inputs in the same tx.
// Check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_lock_twice_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::LockTokenSupply(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::LockTokenSupply(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(lock_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    lock_tx_id.into()
                )
            ))
        );
    });
}

// Issue 2 tokens.
// Lock both tokens in the same transaction.
// Check an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_two_tokens_in_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut rng2 = make_seedable_rng(rng.gen::<Seed>());
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id_1, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let best_block_id = tf.best_block_id();
        let (token_id_2, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            make_issuance(&mut rng2, TokenTotalSupply::Lockable, IsTokenFreezable::No),
        );

        // Lock both tokens tokens same tx
        let lock_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::LockTokenSupply(token_id_1),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::LockTokenSupply(token_id_2),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .build();
        let lock_tx_id = lock_tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(lock_tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    lock_tx_id.into()
                )
            ))
        );
    });
}

// Issue a token.
// Try to mint with insufficient fee, check an error.
// Try to unmint with insufficient fee, check an error.
// Try to lock supply with insufficient fee, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let some_amount = Amount::from_atoms(rng.gen_range(100..100_000));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee - Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        // Try mint with insufficient fee
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, some_amount),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, some_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_id.into()
                )
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::MintTokens(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, some_amount),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let some_amount = Amount::from_atoms(rng.gen_range(100..100_000));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        // Mint some tokens
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            some_amount,
            true,
        );

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee - Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        // Try unmint with insufficient fee
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::MintTokens(token_id, some_amount),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(token_id, some_amount)))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_id.into()
                )
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::MintTokens(token_id, some_amount),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(token_id, some_amount)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_supply_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee - Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        // Try lock with insufficient fee
        let tx_insufficient_fee = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::LockTokenSupply(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_insufficient_fee_id = tx_insufficient_fee.transaction().get_id();
        let result = tf
            .make_block_builder()
            .add_transaction(tx_insufficient_fee)
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_insufficient_fee_id.into(),
                )
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::LockTokenSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Issue a token.
// Mint some tokens and check that the utxo with minted tokens can be spend.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_mint_tokens_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_overspend = (amount_to_mint + Amount::from_atoms(1)).unwrap();

        // Mint some tokens
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
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
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Try to overspend minted amount
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_overspend),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
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
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Try to issue and mint the same token in one transaction, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_mint_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let first_tx_input = TxInput::from_utxo(genesis_source_id.clone(), 0);
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            tf.next_block_height(),
            std::slice::from_ref(&first_tx_input),
        )
        .unwrap();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::TokenDataNotFound(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );
    });
}

// Issue and mint token in different transactions in the same block. Check that it's valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_mint_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));

        let tx_issuance_inputs = vec![TxInput::from_utxo(genesis_source_id, 0)];
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            tf.next_block_height(),
            &tx_issuance_inputs,
        )
        .unwrap();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx_issuance = TransactionBuilder::new()
            .with_witnesses(
                tx_issuance_inputs.iter().map(|_| InputWitness::NoSignature(None)).collect(),
            )
            .with_inputs(tx_issuance_inputs)
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_issuance_id = tx_issuance.transaction().get_id();

        let tx_minting = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_issuance_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();

        tf.make_block_builder()
            .with_transactions(vec![tx_issuance, tx_minting])
            .build_and_process(&mut rng)
            .unwrap();

        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let expected_token_data = tokens_accounting::TokenData::FungibleToken(issuance.into());
        assert_eq!(actual_token_data, Some(expected_token_data));

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));
    });
}

// Issue a token and mint some.
// Create a tx with minting some amount and unminting some amount of tokens.
// Check an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_unmint_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1000..100_000));
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        // Mint some tokens
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // Mint and unmint in the same tx
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(AccountNonce::new(2), AccountCommand::UnmintTokens(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_unmint,
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        // Check the storage
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    tx_id.into()
                )
            ))
        );
    });
}

// Produce `genesis -> a -> b`.
// Block `a` issues a token while block `b` mints some tokens.
// Then produce parallel chain `genesis -> c -> d -> e`.
// Block `c`, `d` and `e` are just empty blocks to trigger the reorg.
// After reorg check that token info was removed from the storage.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_test_simple(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.best_block_id();

        // Create block `a` with token issuance
        let token_issuance =
            make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let (token_id, block_a_id, block_a_change_utxo) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id,
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            token_issuance.clone(),
        );
        assert_eq!(tf.best_block_id(), block_a_id);

        // Create block `b` with token minting
        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (block_b_id, _) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            block_a_id.into(),
            block_a_change_utxo,
            token_id,
            amount_to_mint,
            false,
        );
        assert_eq!(tf.best_block_id(), block_b_id);

        // Check the storage
        let actual_data =
            tf.storage.transaction_ro().unwrap().read_tokens_accounting_data().unwrap();
        let expected_data = tokens_accounting::TokensAccountingData {
            token_data: BTreeMap::from_iter([(
                token_id,
                tokens_accounting::TokenData::FungibleToken(token_issuance.into()),
            )]),
            circulating_supply: BTreeMap::from_iter([(token_id, amount_to_mint)]),
        };
        assert_eq!(actual_data, expected_data);

        // Add blocks from genesis to trigger the reorg
        let block_e_id = tf.create_chain(&genesis_block_id, 3, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), block_e_id);

        // Check the storage
        let actual_data =
            tf.storage.transaction_ro().unwrap().read_tokens_accounting_data().unwrap();
        let expected_data = tokens_accounting::TokensAccountingData {
            token_data: BTreeMap::new(),
            circulating_supply: BTreeMap::new(),
        };
        assert_eq!(actual_data, expected_data);
    });
}

// Produce `genesis -> a -> b -> c`.
// Block `a` produces 2 coins utxo to issue tokens from.
// Block `b` issues token1 and block `c` mints token1.
// Then produce parallel chain `genesis -> a -> d -> e -> f`.
// Where block `d` issues token2 and block `e` mints token2.
// Block `f` is an empty block to trigger the reorg.
// After reorg check that token1 was cleanup from the storage and token2 is stored instead.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_test_2_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut rng2 = make_seedable_rng(rng.gen::<Seed>());
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.best_block_id();

        let amount_to_mint_1 = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let amount_to_mint_2 = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        // create another block with 2 outputs to use them on tokens issuance and get 2 distinct token ids
        let tx_a = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 100).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 100).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_a_id = tx_a.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_a)
            .build_and_process(&mut rng)
            .unwrap();
        let block_a_id = tf.best_block_id();

        // Create block `b` with token1 issuance
        let (token_id_1, block_b_id, block_b_change_utxo) = issue_token_from_block(
            &mut rng,
            &mut tf,
            block_a_id,
            UtxoOutPoint::new(tx_a_id.into(), 0),
            make_issuance(&mut rng2, TokenTotalSupply::Unlimited, IsTokenFreezable::No),
        );
        assert_eq!(tf.best_block_id(), block_b_id);

        // Create block `c` with token1 minting
        let (block_c_id, _) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            block_b_id.into(),
            block_b_change_utxo,
            token_id_1,
            amount_to_mint_1,
            false,
        );
        assert_eq!(tf.best_block_id(), block_c_id);

        // Create block `d` with another token issuance
        let issuance_token_2 =
            make_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::No);
        let (token_id_2, block_d_id, block_d_change_utxo) = issue_token_from_block(
            &mut rng,
            &mut tf,
            block_a_id,
            UtxoOutPoint::new(tx_a_id.into(), 1),
            issuance_token_2.clone(),
        );
        // No reorg
        assert_eq!(tf.best_block_id(), block_c_id);

        // Mint some tokens
        let (block_e_id, _) = mint_tokens_in_block(
            &mut rng,
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
        let block_f = tf.make_block_builder().with_parent(block_e_id.into()).build(&mut rng);
        let block_f_id = block_f.get_id();
        tf.process_block(block_f, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), block_f_id);

        // Check the storage
        let actual_data =
            tf.storage.transaction_ro().unwrap().read_tokens_accounting_data().unwrap();
        let expected_data = tokens_accounting::TokensAccountingData {
            token_data: BTreeMap::from_iter([(
                token_id_2,
                tokens_accounting::TokenData::FungibleToken(issuance_token_2.into()),
            )]),
            circulating_supply: BTreeMap::from_iter([(token_id_2, amount_to_mint_2)]),
        };
        assert_eq!(actual_data, expected_data);
    });
}

// Issue a token.
// Try to mint without providing input signatures, check an error.
// Try to mint with random keys, check an error.
// Mint with controller keys, check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_mint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::PublicKey(controller_pk.clone()),
            is_freezable: IsTokenFreezable::No,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));

        // Try to mint without signature
        let tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
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
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
        ];

        // Try to mint with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Mint with proper keys
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &controller_sk,
                Default::default(),
                Destination::PublicKey(controller_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

// Issue and mint some tokens.
// Try to unmint without providing input signatures, check an error.
// Try to unmint with random keys, check an error.
// Mint with controller keys, check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::PublicKey(controller_pk.clone()),
            is_freezable: IsTokenFreezable::No,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        // Mint some tokens
        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let mint_tx = {
            let input_commitments = vec![
                SighashInputCommitment::None,
                SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
            ];

            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_command(
                        AccountNonce::new(0),
                        AccountCommand::MintTokens(token_id, amount_to_mint),
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_input(
                    utxo_with_change.clone().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(token_supply_change_fee),
                    Destination::AnyoneCanSpend,
                ))
                .add_output(TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, amount_to_mint),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .transaction()
                .clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &controller_sk,
                Default::default(),
                Destination::PublicKey(controller_pk.clone()),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try to unmint without signature
        let tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(AccountNonce::new(1), AccountCommand::UnmintTokens(token_id)),
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
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                amount_to_mint,
            )))
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(
                tf.chainstate
                    .utxo(&UtxoOutPoint::new(mint_tx_id.into(), 0))
                    .unwrap()
                    .unwrap()
                    .take_output(),
            )),
            SighashInputCommitment::Utxo(Cow::Owned(
                tf.chainstate
                    .utxo(&UtxoOutPoint::new(mint_tx_id.into(), 1))
                    .unwrap()
                    .unwrap()
                    .take_output(),
            )),
        ];

        // Try to unmint with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![
                    InputWitness::Standard(account_sig),
                    InputWitness::NoSignature(None),
                    InputWitness::NoSignature(None),
                ],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Unmint with proper keys
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &controller_sk,
                Default::default(),
                Destination::PublicKey(controller_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![
                    InputWitness::Standard(account_sig),
                    InputWitness::NoSignature(None),
                    InputWitness::NoSignature(None),
                ],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

// Issue a token.
// Try to lock the supply without providing input signatures, check an error.
// Try to lock the supply with random keys, check an error.
// Lock the supply with controller keys, check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_lock_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Lockable,
            authority: Destination::PublicKey(controller_pk.clone()),
            is_freezable: IsTokenFreezable::No,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        // Try to lock without signature
        let tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::LockTokenSupply(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
        ];

        // Try to lock with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Lock with proper keys
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &controller_sk,
                Default::default(),
                Destination::PublicKey(controller_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

// Issue a token and mint some with locked outputs for 2 blocks.
// Try transfer tokens in the next block and check it's the timelock error.
// Produce a block.
// Transfer tokens and check that now it's ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_with_timelock(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let amount_to_mint =
            Amount::from_atoms(rng.gen_range(2..SignedAmount::MAX.into_atoms() as u128));
        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        // Mint with locked output
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(2),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let actual_supply = TokensAccountingStorageRead::get_circulating_supply(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        assert_eq!(actual_supply, Some(amount_to_mint));

        // Try spend tokens at once
        let token_mint_outpoint = UtxoOutPoint::new(mint_tx_id.into(), 0);
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(token_mint_outpoint.clone()),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Timelock(TimelockError::HeightLocked(
                        BlockHeight::new(3),
                        BlockHeight::new(4)
                    ))
                )),
            ))
        );

        // Produce 1 more block to get past timelock
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(token_supply_change_fee),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Spend again, now timelock should pass
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::Utxo(token_mint_outpoint.clone()),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn only_ascii_alphanumeric_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.best_block_id();

        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Try not ascii alphanumeric ticker
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let token_ticker = gen_text_with_non_ascii(c, &mut rng, max_ticker_len);
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
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
        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len)
                .as_bytes()
                .to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    })
}

// Issue a token.
// Then in a single tx try mint some tokens, issue another tx and deposit data with not enough fee.
// Then try again but with fee that satisfies all operations.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_mint_and_data_deposit_not_enough_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();
        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
        let data_deposit_fee =
            tf.chainstate.get_chain_config().data_deposit_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let ok_fee = (token_issuance_fee + token_supply_change_fee)
            .and_then(|v| v + data_deposit_fee)
            .unwrap();
        let not_ok_fee = (token_issuance_fee + token_supply_change_fee)
            .and_then(|v| v + data_deposit_fee)
            .and_then(|v| v - Amount::from_atoms(1))
            .unwrap();

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(not_ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .add_output(TxOutput::DataDeposit(Vec::new()))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::Coin
                    ),
                    tx_id.into()
                ))
            )
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::MintTokens(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
                    .add_output(TxOutput::DataDeposit(Vec::new()))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_freezable_supply(#[case] seed: Seed) {
    use common::chain::htlc::{HashedTimelockContract, HtlcSecret};

    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::Yes,
        );

        // Mint some tokens
        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000_000));
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(!data.is_frozen()),
        };

        // Freeze the token
        let freeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(mint_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 5).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_tx_id = freeze_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(freeze_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_frozen()),
        };

        // Try to mint some tokens

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(2),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::TokensAccountingError(
                        tokens_accounting::Error::CannotMintFrozenToken(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Try to lock supply
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(2),
                            AccountCommand::LockTokenSupply(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(freeze_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to transfer frozen tokens
        let result = tf
            .make_block_builder()
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
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to lock then transfer frozen tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::LockThenTransfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                        OutputTimeLock::ForBlockCount(100),
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to burn frozen tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(
                        token_id,
                        amount_to_mint,
                    )))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to spend with htlc
        let htlc = HashedTimelockContract {
            secret_hash: HtlcSecret::new_from_rng(&mut rng).hash(),
            spend_key: Destination::AnyoneCanSpend,
            refund_timelock: OutputTimeLock::ForSeconds(200),
            refund_key: Destination::AnyoneCanSpend,
        };
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Htlc(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Box::new(htlc),
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to implicitly burn frozen tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    // token input
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    // coin input
                    .add_input(
                        TxInput::from_utxo(freeze_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    // coin output
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(token_supply_change_fee),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to create an order with frozen token
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token_id, amount_to_mint),
            OutputValue::Coin(Amount::ZERO),
        );
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Try to create an order with frozen token
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(Amount::ZERO),
            OutputValue::TokenV1(token_id, amount_to_mint),
        );
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(mint_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::CreateOrder(Box::new(order_data)))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Unfreeze the token
        let unfreeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(2),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 3).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let unfreeze_tx_id = unfreeze_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(unfreeze_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(!data.is_frozen()),
        };

        // Now all operations are available again. Try mint/transfer
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(3),
                            AccountCommand::MintTokens(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unfreeze_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Check that if token is frozen/unfrozen by an input command it takes effect only
// after tx is processed. Meaning tx outputs are not aware of state change by inputs in the same tx.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_freeze_unfreeze_takes_effect_after_submit(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::Yes,
        );

        // Mint some tokens
        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000_000));
        let best_block_id = tf.best_block_id();
        let (_, mint_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            amount_to_mint,
            true,
        );

        // Freeze the token and transfer at the same tx
        let freeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
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
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 5).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_tx_id = freeze_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(freeze_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(data.is_frozen()),
        };

        // Try unfreeze the token and transfer at the same tx
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(2),
                            AccountCommand::UnfreezeToken(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(freeze_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(freeze_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin((token_supply_change_fee * 3).unwrap()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Unfreeze the token
        let unfreeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(2),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_supply_change_fee * 3).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let unfreeze_tx_id = unfreeze_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(unfreeze_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        match actual_token_data.unwrap() {
            tokens_accounting::TokenData::FungibleToken(data) => assert!(!data.is_frozen()),
        };

        // Now all operations are available again. Try mint/transfer
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(3),
                            AccountCommand::MintTokens(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unfreeze_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_mint),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_freeze_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let ok_fee = tf.chainstate.get_chain_config().token_freeze_fee(BlockHeight::zero());
        let not_ok_fee = (ok_fee - Amount::from_atoms(1)).unwrap();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::Yes,
        );

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(not_ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        // Try freeze with insufficient fee
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_id.into()
                )
            ))
        );

        // Freeze with proper fee
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_unfreeze_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let ok_fee = tf.chainstate.get_chain_config().token_freeze_fee(BlockHeight::zero());
        let not_ok_fee = (ok_fee - Amount::from_atoms(1)).unwrap();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::Yes,
        );

        let freeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((ok_fee * 2).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_tx_id = freeze_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(freeze_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(freeze_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(not_ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(ok_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        // Try unfreeze with insufficient fee
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_id.into()
                )
            ))
        );

        // Unfreeze with proper fee
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::UnfreezeToken(token_id),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Issue a token.
// Try to freeze without providing input signatures, check an error.
// Try to freeze with random keys, check an error.
// Freeze with controller keys, check ok.
// Try to unfreeze without providing input signatures, check an error.
// Try to unfreeze with random keys, check an error.
// Unfreeze with controller keys, check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_freeze_unfreeze(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut rng2 = make_seedable_rng(rng.gen::<Seed>());
        let mut rng3 = make_seedable_rng(rng.gen::<Seed>());
        let mut tf = TestFramework::builder(&mut rng).build();
        let token_freeze_fee =
            tf.chainstate.get_chain_config().token_freeze_fee(BlockHeight::zero());
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::PublicKey(controller_pk.clone()),
            is_freezable: IsTokenFreezable::Yes,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        // Try to freeze without signature
        let freeze_tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_freeze_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_tx_id = freeze_tx_no_signatures.transaction().get_id();

        let result = tf
            .make_block_builder()
            .add_transaction(freeze_tx_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
        ];

        let mut replace_signature_for_tx = |tx, sk, pk, input_commitments| {
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &sk,
                Default::default(),
                Destination::PublicKey(pk),
                &tx,
                input_commitments,
                0,
                &mut rng3,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        // Try to freeze with wrong signature
        let (random_sk, random_pk) = PrivateKey::new_from_rng(&mut rng2, KeyKind::Secp256k1Schnorr);
        let signed_tx = replace_signature_for_tx(
            freeze_tx_no_signatures.transaction().clone(),
            random_sk,
            random_pk,
            &input_commitments,
        );

        let result = tf.make_block_builder().add_transaction(signed_tx).build_and_process(&mut rng);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Freeze with proper keys
        let signed_tx = replace_signature_for_tx(
            freeze_tx_no_signatures.transaction().clone(),
            controller_sk.clone(),
            controller_pk.clone(),
            &input_commitments,
        );
        tf.make_block_builder()
            .add_transaction(signed_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try to unfreeze without signature
        let unfreeze_tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(unfreeze_tx_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(
                tf.chainstate
                    .utxo(&UtxoOutPoint::new(freeze_tx_id.into(), 0))
                    .unwrap()
                    .unwrap()
                    .take_output(),
            )),
        ];

        // Try unfreeze with random signature
        let (random_sk, random_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let signed_tx = replace_signature_for_tx(
            unfreeze_tx_no_signatures.transaction().clone(),
            random_sk,
            random_pk,
            &input_commitments,
        );

        let result = tf.make_block_builder().add_transaction(signed_tx).build_and_process(&mut rng);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Unfreeze with controller signature
        let signed_tx = replace_signature_for_tx(
            unfreeze_tx_no_signatures.transaction().clone(),
            controller_sk,
            controller_pk,
            &input_commitments,
        );
        tf.make_block_builder()
            .add_transaction(signed_tx)
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Issue a token.
// Try to change authority without providing input signatures, check an error.
// Try to change authority with random key, check an error.
// Change the authority with proper key, check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_signature_on_change_authority(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.genesis().get_id();

        let (original_sk, original_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Lockable,
            authority: Destination::PublicKey(original_pk.clone()),
            is_freezable: IsTokenFreezable::No,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        let (new_sk, new_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority = Destination::PublicKey(new_pk.clone());

        // Try to change authority without signature
        let tx_1_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    tf.chain_config().token_change_authority_fee(BlockHeight::zero()),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_1_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
        ];

        // Try to change authority with wrong signature
        let tx = {
            let tx = tx_1_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Change authority with proper keys
        let tx = {
            let tx = tx_1_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &original_sk,
                Default::default(),
                Destination::PublicKey(original_pk.clone()),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };
        let tx_1_id = tx.transaction().get_id();

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        // Now try to change authority once more with original key
        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(
                tf.chainstate
                    .utxo(&UtxoOutPoint::new(tx_1_id.into(), 0))
                    .unwrap()
                    .unwrap()
                    .take_output(),
            )),
        ];

        let tx_2_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_1_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();

        let tx = {
            let tx = tx_2_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &original_sk,
                Default::default(),
                Destination::PublicKey(original_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Change authority with new keys
        let tx = {
            let tx = tx_2_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &new_sk,
                Default::default(),
                Destination::PublicKey(new_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_change_authority(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let original_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(original_token_data) =
            original_token_data.unwrap();
        assert_eq!(
            original_token_data.authority(),
            &Destination::AnyoneCanSpend
        );

        let (_, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority = Destination::PublicKey(some_pk);
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::ChangeTokenAuthority(token_id, new_authority.clone()),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(actual_token_data) =
            actual_token_data.unwrap();
        assert_eq!(actual_token_data.authority(), &new_authority);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_change_authority_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let original_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(original_token_data) =
            original_token_data.unwrap();
        assert_eq!(
            original_token_data.authority(),
            &Destination::AnyoneCanSpend
        );

        let (_, pk_1) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority_1 = Destination::PublicKey(pk_1);
        let (_, pk_2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority_2 = Destination::PublicKey(pk_2);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority_1),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority_2.clone()),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        // Check result
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::MultipleAccountCommands,
                    tx_id.into()
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_change_authority_for_frozen_token(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let unfreeze_fee = tf.chain_config().token_freeze_fee(BlockHeight::zero());
        let change_authority_fee =
            tf.chain_config().token_change_authority_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::Yes,
        );

        // Freeze the token
        let freeze_token_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((change_authority_fee + unfreeze_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_token_tx_id = freeze_token_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(freeze_token_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try change authority when the token is frozen
        let (_, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority = Destination::PublicKey(some_pk);

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::ChangeTokenAuthority(token_id, new_authority.clone()),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(freeze_token_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Unfreeze token
        let unfreeze_token_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_token_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change_authority_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let unfreeze_token_tx_id = unfreeze_token_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(unfreeze_token_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Change authority after unfreeze
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(2),
                            AccountCommand::ChangeTokenAuthority(token_id, new_authority.clone()),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unfreeze_token_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(actual_token_data) =
            actual_token_data.unwrap();
        assert_eq!(actual_token_data.authority(), &new_authority);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_authority_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_change_authority_fee =
            tf.chainstate.get_chain_config().token_change_authority_fee(BlockHeight::zero());

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let tx_with_fee = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(utxo_with_change),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_change_authority_fee - Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_change_authority_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_with_fee_id = tx_with_fee.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(tx_with_fee)
            .build_and_process(&mut rng)
            .unwrap();

        let (_, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let new_authority = Destination::PublicKey(some_pk);

        // Try change authority with insufficient fee
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority.clone()),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_with_fee_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToViolateFeeRequirements,
                    tx_id.into(),
                )
            ))
        );

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::ChangeTokenAuthority(token_id, new_authority),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(tx_with_fee_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

// Produce `genesis -> a` chain, where block `a` transfers coins and issue a token in separate txs.
//
// It's vital to have 2 txs in that order because on disconnect token undo would be performed first
// and tokens::BlockUndo object would be erased. But then when transfer tx is disconnected tokens::BlockUndo
// is fetched and checked again, which should work fine and just return None.
//
// Then produce a parallel `genesis -> b -> c` that should trigger a in-memory reorg for block `a`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_tokens_tx_with_simple_tx(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut tf = TestFramework::builder(&mut rng).build();
    let genesis_block_id: Id<GenBlock> = tf.genesis().get_id().into();
    let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

    // produce block `a` with transfer tx ans issue token tx
    let transfer_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_block_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(token_issuance_fee),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let transfer_tx_id = transfer_tx.transaction().get_id();

    let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
    let issue_token_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(transfer_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
        .build();

    tf.make_block_builder()
        .with_transactions(vec![transfer_tx, issue_token_tx])
        .build_and_process(&mut rng)
        .unwrap();

    // produce block at height 2 that should trigger in memory reorg for block `b`
    let new_chain_block_id = tf.create_chain(&tf.genesis().get_id().into(), 2, &mut rng).unwrap();
    assert_eq!(new_chain_block_id, tf.best_block_id());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_same_token_alternative_pos_chain(#[case] seed: Seed) {
    use chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker;
    use common::{
        chain::{config::create_unit_test_config, PoolId},
        primitives::H256,
    };
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey};

    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
        let amount_to_stake = create_unit_test_config().min_stake_pool_pledge();

        let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            amount_to_stake,
            vrf_pk.clone(),
        );

        let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
            &mut rng,
            (amount_to_stake * 2).unwrap(),
            genesis_pool_id,
            stake_pool_data,
        )
        .build();
        let target_block_time = chain_config.target_block_spacing();
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        let genesis_block_id = tf.genesis().get_id();
        let token_supply_change_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

        //issue a token
        let issuance = make_issuance(
            &mut rng,
            TokenTotalSupply::Fixed(Amount::from_atoms(100)),
            IsTokenFreezable::No,
        );
        let issue_token_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_supply_change_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            tf.next_block_height(),
            issue_token_tx.inputs(),
        )
        .unwrap();
        let tx_id = issue_token_tx.transaction().get_id();
        tf.make_pos_block_builder()
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .add_transaction(issue_token_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Mint some tokens to increase circulating supply
        let mint_block_index = tf
            .make_pos_block_builder()
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::MintTokens(token_id, Amount::from_atoms(5)),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        UtxoOutPoint::new(tx_id.into(), 0).into(),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(5)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(
            Id::<GenBlock>::from(*mint_block_index.block_id()),
            tf.best_block_id()
        );

        // issue same token in alternative chain
        let alt_block_a = tf
            .make_pos_block_builder()
            .with_parent(genesis_block_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_block_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin((token_supply_change_fee * 2).unwrap()),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
                    .build(),
            )
            .build(&mut rng);
        let alt_block_a_id = alt_block_a.get_id();
        tf.process_block(alt_block_a, BlockSource::Local).unwrap();

        assert_ne!(Id::<GenBlock>::from(alt_block_a_id), tf.best_block_id());
        assert_eq!(
            Id::<GenBlock>::from(*mint_block_index.block_id()),
            tf.best_block_id()
        );

        let alt_block_b = tf
            .make_pos_block_builder()
            .with_parent(alt_block_a_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let alt_block_b_id = alt_block_b.get_id();
        tf.process_block(alt_block_b, BlockSource::Local).unwrap();

        assert_ne!(Id::<GenBlock>::from(alt_block_b_id), tf.best_block_id());
        assert_eq!(
            Id::<GenBlock>::from(*mint_block_index.block_id()),
            tf.best_block_id()
        );

        // Trigger a reorg
        let alt_block_c = tf
            .make_pos_block_builder()
            .with_parent(alt_block_b_id.into())
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        let alt_block_c_id = alt_block_c.get_id();
        tf.process_block(alt_block_c, BlockSource::Local).unwrap();

        assert_eq!(Id::<GenBlock>::from(alt_block_c_id), tf.best_block_id());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_change_metadata_uri(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        // too large metadata
        let max_len = tf.chain_config().token_max_uri_len();
        {
            let too_large_metadata_uri =
                random_ascii_alphanumeric_string(&mut rng, (max_len + 1)..(max_len * 100))
                    .as_bytes()
                    .to_vec();
            let result = tf
                .make_block_builder()
                .add_transaction(
                    TransactionBuilder::new()
                        .add_input(
                            TxInput::from_command(
                                AccountNonce::new(0),
                                AccountCommand::ChangeTokenMetadataUri(
                                    token_id,
                                    too_large_metadata_uri,
                                ),
                            ),
                            InputWitness::NoSignature(None),
                        )
                        .add_input(
                            utxo_with_change.clone().into(),
                            InputWitness::NoSignature(None),
                        )
                        .build(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    chainstate::CheckBlockError::CheckTransactionFailed(
                        chainstate::CheckBlockTransactionsError::CheckTransactionError(
                            tx_verifier::CheckTransactionError::TokensError(
                                TokensError::TokenMetadataUriTooLarge(token_id)
                            )
                        )
                    )
                ))
            );
        }

        let new_metadata_uri =
            random_ascii_alphanumeric_string(&mut rng, 1..=max_len).as_bytes().to_vec();
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(actual_token_data) =
            actual_token_data.unwrap();
        assert_eq!(actual_token_data.metadata_uri(), &new_metadata_uri);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_change_metadata_for_frozen_token(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let unfreeze_fee = tf.chain_config().token_freeze_fee(BlockHeight::zero());
        let change_metadata_fee = tf.chain_config().token_change_metadata_uri_fee();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::Yes,
        );

        // Freeze the token
        let freeze_token_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((change_metadata_fee + unfreeze_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_token_tx_id = freeze_token_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(freeze_token_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Try change metadata when the token is frozen
        let new_metadata_uri =
            random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(freeze_token_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );

        // Unfreeze token
        let unfreeze_token_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(1),
                    AccountCommand::UnfreezeToken(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(freeze_token_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change_metadata_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let unfreeze_token_tx_id = unfreeze_token_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(unfreeze_token_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // Change metadata after unfreeze
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(2),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unfreeze_token_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Check result
        let actual_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(actual_token_data) =
            actual_token_data.unwrap();
        assert_eq!(actual_token_data.metadata_uri(), &new_metadata_uri);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_metadata_uri_change(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.best_block_id();

        // Create block `a` with token issuance
        let token_issuance =
            make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let (token_id, block_a_id, block_a_change_utxo) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id,
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            token_issuance.clone(),
        );
        assert_eq!(tf.best_block_id(), block_a_id);

        // Create block `b` with token minting
        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (block_b_id, mint_tokens_tx_id) = mint_tokens_in_block(
            &mut rng,
            &mut tf,
            block_a_id.into(),
            block_a_change_utxo,
            token_id,
            amount_to_mint,
            true,
        );
        assert_eq!(tf.best_block_id(), block_b_id);

        let original_token_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token_id,
        )
        .unwrap();
        let tokens_accounting::TokenData::FungibleToken(original_token_data) =
            original_token_data.unwrap();
        let original_metadata_uri = original_token_data.metadata_uri().to_owned();

        // Create block `c` which changes token metadata uri
        let new_metadata_uri =
            random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(1),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_tokens_tx_id.into(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();

        // Check the storage
        let tokens_accounting::TokenData::FungibleToken(actual_new_token_data) = tf
            .storage
            .transaction_ro()
            .unwrap()
            .read_tokens_accounting_data()
            .unwrap()
            .token_data
            .get(&token_id)
            .cloned()
            .unwrap();
        let actual_new_metadata_uri = actual_new_token_data.metadata_uri();
        assert_eq!(actual_new_metadata_uri, new_metadata_uri);

        // Add blocks from genesis to trigger the reorg
        let block_e_id = tf.create_chain((&block_b_id).into(), 2, &mut rng).unwrap();
        assert_eq!(tf.best_block_id(), block_e_id);

        // Check the storage
        let tokens_accounting::TokenData::FungibleToken(actual_token_data) = tf
            .storage
            .transaction_ro()
            .unwrap()
            .read_tokens_accounting_data()
            .unwrap()
            .token_data
            .get(&token_id)
            .cloned()
            .unwrap();
        let actual_metadata_uri = actual_token_data.metadata_uri();
        assert_eq!(actual_metadata_uri, original_metadata_uri);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_change_metadata_uri_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        // activate feature at height 3
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .change_token_metadata_uri_activated(
                                        common::chain::ChangeTokenMetadataUriActivated::No,
                                    )
                                    .build(),
                            ),
                            (
                                BlockHeight::new(3),
                                ChainstateUpgradeBuilder::latest()
                                    .change_token_metadata_uri_activated(
                                        common::chain::ChangeTokenMetadataUriActivated::Yes,
                                    )
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::No,
        );

        let new_metadata_uri =
            random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();

        // Try to change metadata before activation, check an error
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::ChangeTokenMetadataUriNotActivated
                    )
                )
            ))
        );

        // produce an empty block
        tf.make_block_builder().build_and_process(&mut rng).unwrap();

        // now it should be possible to use htlc output
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_command(
                            AccountNonce::new(0),
                            AccountCommand::ChangeTokenMetadataUri(
                                token_id,
                                new_metadata_uri.clone(),
                            ),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        utxo_with_change.clone().into(),
                        InputWitness::NoSignature(None),
                    )
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn only_authority_can_change_metadata_uri(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_block_id = tf.genesis().get_id();

        let (original_sk, original_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Lockable,
            authority: Destination::PublicKey(original_pk.clone()),
            is_freezable: IsTokenFreezable::No,
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        let new_metadata_uri =
            random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();

        // Try to change metadata without a signature
        let tx_1_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    tf.chain_config().token_change_authority_fee(BlockHeight::zero()),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_1_no_signatures.clone())
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureNotFound)
                ))
            ))
        );

        let input_commitments = vec![
            SighashInputCommitment::None,
            SighashInputCommitment::Utxo(Cow::Owned(tf.utxo(&utxo_with_change).take_output())),
        ];

        // Try to change metadata with wrong signature
        let tx = {
            let tx = tx_1_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    ScriptError::Signature(DestinationSigError::SignatureVerificationFailed)
                ))
            ))
        );

        // Change metadata with proper keys
        let tx = {
            let tx = tx_1_no_signatures.transaction().clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &original_sk,
                Default::default(),
                Destination::PublicKey(original_pk.clone()),
                &tx,
                &input_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_id_generation_v1_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        // activate feature at height 3
        let fork_height = BlockHeight::new(3);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .token_id_generation_version(
                                        common::chain::TokenIdGenerationVersion::V0,
                                    )
                                    .build(),
                            ),
                            (
                                fork_height,
                                ChainstateUpgradeBuilder::latest()
                                    .token_id_generation_version(
                                        common::chain::TokenIdGenerationVersion::V1,
                                    )
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        // Create a token just so that there is an account to use in inputs
        let (token_id_0, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Lockable,
            IsTokenFreezable::Yes,
        );

        // Create a token from account input
        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();
        let token_change_authority_fee =
            tf.chainstate.get_chain_config().token_change_authority_fee(BlockHeight::zero());
        let tx1_first_input = TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::LockTokenSupply(token_id_0),
        );
        let tx1_first_utxo_input = TxInput::Utxo(utxo_with_change);

        let tx1 = TransactionBuilder::new()
            .add_input(tx1_first_input.clone(), InputWitness::NoSignature(None))
            .add_input(
                tx1_first_utxo_input.clone(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_issuance_fee + token_change_authority_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();

        let issue_token_1_tx_id = tx1.transaction().get_id();
        let token1_id = make_token_id(
            tf.chain_config(),
            tf.next_block_height(),
            tx1.transaction().inputs(),
        )
        .unwrap();

        tf.make_block_builder()
            .add_transaction(tx1)
            .build_and_process(&mut rng)
            .unwrap();

        let token_1_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token1_id,
        )
        .unwrap();
        assert!(token_1_data.is_some());
        assert_eq!(token1_id, TokenId::from_tx_input(&tx1_first_input));
        assert_ne!(token1_id, TokenId::from_tx_input(&tx1_first_utxo_input));

        let token2_creation_height = tf.next_block_height();

        // Sanity check
        assert_eq!(token2_creation_height, fork_height);

        // Check that after the fork a token is issued not from the first input but from the first utxo input.
        let tx2_first_input = TxInput::AccountCommand(
            AccountNonce::new(1),
            AccountCommand::ChangeTokenAuthority(token_id_0, Destination::AnyoneCanSpend),
        );
        let tx2_first_utxo_input = TxInput::from_utxo(issue_token_1_tx_id.into(), 0);

        let tx2 = TransactionBuilder::new()
            .add_input(tx2_first_input.clone(), InputWitness::NoSignature(None))
            .add_input(
                tx2_first_utxo_input.clone(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
            .build();

        let token2_id = make_token_id(
            tf.chain_config(),
            token2_creation_height,
            tx2.transaction().inputs(),
        )
        .unwrap();
        // token2_id was created from the first utxo inputs.
        assert_eq!(token2_id, TokenId::from_tx_input(&tx2_first_utxo_input));

        // The id that token2 would have before the fork.
        let token2_id_before_fork = make_token_id(
            tf.chain_config(),
            token2_creation_height.prev_height().unwrap(),
            tx2.transaction().inputs(),
        )
        .unwrap();
        // Sanity check - before the fork the id of token2 would be generated from the first input
        // and it would be different from token2_id.
        assert_eq!(
            token2_id_before_fork,
            TokenId::from_tx_input(&tx2_first_input)
        );
        assert_ne!(token2_id, token2_id_before_fork);

        tf.make_block_builder()
            .add_transaction(tx2)
            .build_and_process(&mut rng)
            .unwrap();

        let token_2_data = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token2_id,
        )
        .unwrap();
        assert!(token_2_data.is_some());

        let token_2_data_for_invalid_token_id = TokensAccountingStorageRead::get_token_data(
            &tf.storage.transaction_ro().unwrap(),
            &token2_id_before_fork,
        )
        .unwrap();
        assert!(token_2_data_for_invalid_token_id.is_none());
    });
}

// Transferring zero tokens is allowed.
// TODO: perhaps we should prohibit it?
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn zero_amount_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let tx = TransactionBuilder::new()
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::ZERO),
                Destination::AnyoneCanSpend,
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    });
}

// For a frozen token, even zero amount transfers are not allowed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn zero_amount_transfer_of_frozen_token(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token_id, _, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::Yes,
        );

        let change_coins = tf.coin_amount_from_utxo(&utxo_with_change);
        let token_freeze_fee = tf.chain_config().token_freeze_fee(BlockHeight::zero());

        let freeze_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((change_coins - token_freeze_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let freeze_tx_id = freeze_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(freeze_tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let utxo_with_change = UtxoOutPoint::new(freeze_tx_id.into(), 0);

        let tx = TransactionBuilder::new()
            .add_input(utxo_with_change.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::ZERO),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
            ))
        );
    });
}
