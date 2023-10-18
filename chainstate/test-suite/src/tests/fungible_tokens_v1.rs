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

use std::collections::BTreeMap;

use chainstate::{
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_storage::BlockchainStorageRead;
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::{standard_signature::StandardInputSignature, InputWitness},
        tokens::{
            make_token_id, TokenId, TokenIssuance, TokenIssuanceV1, TokenIssuanceVersion,
            TokenTotalSupply,
        },
        AccountNonce, AccountSpending, AccountType, Block, ChainstateUpgrade, Destination,
        GenBlock, NetUpgrades, OutPointSourceId, SignedTransaction, TokenOutput, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{signed_amount::SignedAmount, Amount, BlockHeight, Id, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::{CryptoRng, Rng},
};
use rstest::rstest;
use test_utils::{
    gen_text_with_non_ascii,
    random::{make_seedable_rng, Seed},
    random_string, split_value,
};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::error::TokenIssuanceError;
use tx_verifier::transaction_verifier::signature_destination_getter::SignatureDestinationGetterError;

fn make_test_framework_with_v1(rng: &mut (impl Rng + CryptoRng)) -> TestFramework {
    TestFramework::builder(rng)
        .with_chain_config(
            common::chain::config::Builder::test_chain()
                .chainstate_upgrades(
                    NetUpgrades::initialize(vec![(
                        BlockHeight::zero(),
                        ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                    )])
                    .unwrap(),
                )
                .genesis_unittest(Destination::AnyoneCanSpend)
                .build(),
        )
        .build()
}

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

fn unmint_tokens_in_block(
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    token_id: TokenId,
    utxo_to_burn_tokens: UtxoOutPoint,
    utxo_to_pay_fee: UtxoOutPoint,
    amount_to_unmint: Amount,
) -> (Id<Block>, Id<Transaction>) {
    let token_min_supply_change_fee =
        tf.chainstate.get_chain_config().token_min_supply_change_fee();

    let nonce = BlockchainStorageRead::get_account_nonce_count(
        &tf.storage,
        AccountType::TokenSupply(token_id),
    )
    .unwrap()
    .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

    let fee_input_utxo_coins = chainstate_test_framework::get_output_value(
        tf.chainstate.utxo(&utxo_to_pay_fee).unwrap().unwrap().output(),
    )
    .unwrap()
    .coin_amount()
    .unwrap();

    let tokens_input_utxo_amount = match chainstate_test_framework::get_output_value(
        tf.chainstate.utxo(&utxo_to_burn_tokens).unwrap().unwrap().output(),
    )
    .unwrap()
    {
        OutputValue::Coin(_) | OutputValue::TokenV0(_) => panic!("Invalid input to burn tokens"),
        OutputValue::TokenV1(_, amount) => amount,
    };

    let tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_account(nonce, AccountSpending::TokenCirculatingSupply(token_id)),
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
        .add_output(TxOutput::Burn(OutputValue::Coin(
            token_min_supply_change_fee,
        )))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(
                token_id,
                (tokens_input_utxo_amount - amount_to_unmint).unwrap(),
            ),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((fee_input_utxo_coins - token_min_supply_change_fee).unwrap()),
            Destination::AnyoneCanSpend,
        ));

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
        let mut tf = make_test_framework_with_v1(&mut rng);
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

// TokensV1 issuance should be an error before V1 fork is activated
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_before_v1_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgrade::new(TokenIssuanceVersion::V0),
                            ),
                            (
                                BlockHeight::new(2),
                                ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                        Box::new(issuance.clone()),
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::TokensError(
                    TokensError::UnsupportedTokenIssuanceVersion(_, _)
                ))
            ))
        ));

        // Add block to activate fork
        let coin_transfer_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(outpoint_source_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let coin_transfer_tx_id = coin_transfer_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(coin_transfer_tx)
            .build_and_process()
            .unwrap();

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(coin_transfer_tx_id.into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                        Box::new(issuance),
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process()
            .unwrap();
    });
}

// Try issuing a token but burn less coins than required by issuance fee; check that's an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_not_enough_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id.clone(), 0),
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

        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::TokensOp(TokenOutput::IssueFungibleToken(
                        Box::new(issuance.clone()),
                    )))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process()
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
        let mut tf = make_test_framework_with_v1(&mut rng);

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
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::ZERO),
                        Destination::AnyoneCanSpend,
                    ))
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
        let mut tf = make_test_framework_with_v1(&mut rng);
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
        let mut tf = make_test_framework_with_v1(&mut rng);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let total_supply = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Fixed(total_supply));

        // Mint all the tokens up to the total supply
        let best_block_id = tf.best_block_id();
        let (_, mint_total_supply_tx_id) = mint_tokens_in_block(
            &mut tf,
            best_block_id,
            utxo_with_change,
            token_id,
            total_supply,
            true,
        );

        // Mint 1 tokens over the limit
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(1),
                            AccountSpending::TokenTotalSupply(token_id, Amount::from_atoms(1)),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(mint_total_supply_tx_id.into(), 2),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
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
                        Amount::from_atoms(1),
                        total_supply,
                        token_id
                    )
                )
            ))
        );

        // Unmint 1 token
        let best_block_id = tf.best_block_id();
        let (_, unmint_1_token_tx_id) = unmint_tokens_in_block(
            &mut tf,
            best_block_id,
            token_id,
            UtxoOutPoint::new(mint_total_supply_tx_id.into(), 1),
            UtxoOutPoint::new(mint_total_supply_tx_id.into(), 2),
            Amount::from_atoms(1),
        );

        // Try mint 2 tokens which is still over the limit
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(2),
                            AccountSpending::TokenTotalSupply(token_id, Amount::from_atoms(2)),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unmint_1_token_tx_id.into(), 3),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
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
                        Amount::from_atoms(2),
                        total_supply,
                        token_id
                    )
                )
            ))
        );

        // Unmint n tokens
        // Note: -1 because 1 was unminted previously
        let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..total_supply.into_atoms() - 1));
        let best_block_id = tf.best_block_id();
        let (_, unmint_n_tokens_tx_id) = unmint_tokens_in_block(
            &mut tf,
            best_block_id,
            token_id,
            UtxoOutPoint::new(unmint_1_token_tx_id.into(), 2),
            UtxoOutPoint::new(unmint_1_token_tx_id.into(), 3),
            amount_to_unmint,
        );

        // Try mint n+1 tokens which is still over the limit
        // Note: +2 below because 1 was unminted previously and 1 to get over the limit
        let amount_to_unmint_plus_1 = (amount_to_unmint + Amount::from_atoms(2)).unwrap();
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(3),
                            AccountSpending::TokenTotalSupply(token_id, amount_to_unmint_plus_1),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unmint_n_tokens_tx_id.into(), 3),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, amount_to_unmint_plus_1),
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
                        amount_to_unmint_plus_1,
                        total_supply,
                        token_id
                    )
                )
            ))
        );

        // Mint exactly the amount that was totally unminted
        let amount_to_mint = (amount_to_unmint + Amount::from_atoms(1)).unwrap();
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(3),
                            AccountSpending::TokenTotalSupply(token_id, amount_to_mint),
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(unmint_n_tokens_tx_id.into(), 3),
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
            .build_and_process()
            .unwrap();

        assert_eq!(
            tf.storage.get_circulating_supply(&token_id).unwrap().unwrap(),
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
        let mut tf = make_test_framework_with_v1(&mut rng);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..=i128::MAX as u128));
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        // Mint more than i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenTotalSupply(
                        token_id,
                        Amount::from_atoms(i128::MAX as u128 + 1),
                    ),
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
        let result = tf.make_block_builder().add_transaction(mint_tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensAccountingError(
                    tokens_accounting::Error::AccountingError(
                        accounting::Error::ArithmeticErrorToSignedFailed
                    )
                )
            ))
        );

        // Mint tokens <= i128::MAX
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
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);

        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();

        let max_amount_to_mint = Amount::from_atoms(i128::MAX as u128);
        let (token_id, _, utxo_with_change) =
            issue_token_from_genesis(&mut rng, &mut tf, TokenTotalSupply::Unlimited);

        // Mint tokens i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenTotalSupply(token_id, max_amount_to_mint),
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
                OutputValue::TokenV1(token_id, max_amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();

        let actual_supply =
            TokensAccountingStorageRead::get_circulating_supply(&tf.storage, &token_id).unwrap();
        assert_eq!(actual_supply, Some(max_amount_to_mint));

        // Try mint one more over i128::MAX
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(1),
                    AccountSpending::TokenTotalSupply(token_id, Amount::from_atoms(1)),
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
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let result = tf.make_block_builder().add_transaction(mint_tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::TransactionVerifierError(
                tx_verifier::TransactionVerifierStorageError::TokensAccountingError(
                    tokens_accounting::Error::StorageWrite
                )
            ))
        );

        // Try mint random number over i128::MAX
        let random_amount = Amount::from_atoms(rng.gen_range(0..i128::MAX as u128));
        let mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(1),
                    AccountSpending::TokenTotalSupply(token_id, random_amount),
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
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();
        let result = tf.make_block_builder().add_transaction(mint_tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::TransactionVerifierError(
                tx_verifier::TransactionVerifierStorageError::TokensAccountingError(
                    tokens_accounting::Error::StorageWrite
                )
            ))
        );
    });
}

// Issue a token and type to mint from different account types.
// Mint from TokenCirculatingSupply and check an error.
// Mint from TokenLockSupply and check an error.
// Mint from TokenTotalSupply and check ok.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_from_wrong_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue a token and try to print some tokens:
// Mint some tokens but skip account input, check an error;
// Mint some tokens but provide les in an account input than in the output, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_to_print_money_on_mint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue a token, mint some and try to burn tokens and spend from total supply account.
// Check that it's not an error an that the tokens actually are minted
// and burned without unminting.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_from_total_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

        // Spending from TokenTotalSupply and burning is not an error
        // because it's basically minting new tokens without outputs (that can be scooped by miner)
        // and burning the tokens from inputs without unminting.
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(1),
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

// Issue a token, mint some and try to burn tokens and spend from lock supply account.
// Check that it's not an error and that the supply is actually locked
// and tokens are burned without unminting.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_from_lock_supply_account(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

        // Unminting from TokenSupplyLock is not an error because it's basically just locking and burning at once
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_account(
                            AccountNonce::new(1),
                            AccountSpending::TokenSupplyLock(token_id),
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
        assert_eq!(circulating_supply, Some(amount_to_mint));

        let actual_token_data =
            TokensAccountingStorageRead::get_token_data(&tf.storage, &token_id).unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue and mint some tokens.
// On unmint the number of burned tokens in output is less then in the input utxo.
// Check that exactly burned amount was unminted (not the amount from input utxo)
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_less_than_input_on_unmint(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue and mint some tokens.
// On unmint provide a utxo that has less tokens that burned output.
// Check that it's an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_less_by_providing_smaller_input_utxo(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue and mint some tokens.
// Unmint by providing multiple input utxos with tokens and burning them in multiple outputs.
// Check that the total tokens taken from circulation is a sum of burned outputs.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_using_multiple_burn_utxos(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue and mint some tokens.
// Lock the supply.
// Check that after that no more tokens can be minted or unminted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_lockable_supply(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);
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
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue a token and lock the supply.
// Try to lock once more and check the error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_lock_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);
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

// Issue a token.
// Try to mint with insufficient fee, check an error.
// Try to unmint with insufficient fee, check an error.
// Try to lock supply with insufficient fee, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn supply_change_fees(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Issue a token.
// Mint some tokens and check that the utxo with minted tokens can be spend.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_mint_tokens_output(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);

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

// Try to issue and mint the same token in one transaction, check an error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_mint_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);
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

// Issue and mint token in different transactions in the same block. Check that it's valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_mint_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v1(&mut rng);
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
        let mut tf = make_test_framework_with_v1(&mut rng);
        let genesis_block_id = tf.best_block_id();

        // Create block `b` with token issuance

        let token_issuance = make_issuance(&mut rng, TokenTotalSupply::Unlimited);
        let (token_id, block_b_id, block_b_change_utxo) = issue_token_from_block(
            &mut tf,
            genesis_block_id,
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            token_issuance.clone(),
        );
        assert_eq!(tf.best_block_id(), block_b_id);

        // Create block `c` with token minting
        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let (block_c_id, _) = mint_tokens_in_block(
            &mut tf,
            block_b_id.into(),
            block_b_change_utxo,
            token_id,
            amount_to_mint,
            false,
        );
        assert_eq!(tf.best_block_id(), block_c_id);

        // Check the storage
        let actual_data = tf.storage.read_tokens_accounting_data().unwrap();
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
        let actual_data = tf.storage.read_tokens_accounting_data().unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);
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
        let actual_data = tf.storage.read_tokens_accounting_data().unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);
        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::PublicKey(controller_pk.clone()),
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));

        // Try to mint without signature
        let tx_no_signatures = TransactionBuilder::new()
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

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureNotFound
                )
            ))
        );

        let inputs_utxos = vec![
            None,
            tf.chainstate.utxo(&utxo_with_change).unwrap().map(|utxo| utxo.output().clone()),
        ];
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Try to mint with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &inputs_utxos_refs,
                0,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureVerificationFailed
                )
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
                &inputs_utxos_refs,
                0,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);
        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::PublicKey(controller_pk.clone()),
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        // Mint some tokens
        let amount_to_mint = Amount::from_atoms(rng.gen_range(2..100_000_000));
        let mint_tx = {
            let inputs_utxos = vec![
                None,
                tf.chainstate.utxo(&utxo_with_change).unwrap().map(|utxo| utxo.output().clone()),
            ];
            let inputs_utxos_refs =
                inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

            let tx = TransactionBuilder::new()
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
                .build()
                .transaction()
                .clone();

            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &controller_sk,
                Default::default(),
                Destination::PublicKey(controller_pk.clone()),
                &tx,
                &inputs_utxos_refs,
                0,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };
        let mint_tx_id = mint_tx.transaction().get_id();
        tf.make_block_builder().add_transaction(mint_tx).build_and_process().unwrap();

        // Try to unmint without signature
        let tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(1),
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
                amount_to_mint,
            )))
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureNotFound
                )
            ))
        );

        let inputs_utxos = vec![
            None,
            tf.chainstate
                .utxo(&UtxoOutPoint::new(mint_tx_id.into(), 0))
                .unwrap()
                .map(|utxo| utxo.output().clone()),
            tf.chainstate
                .utxo(&UtxoOutPoint::new(mint_tx_id.into(), 1))
                .unwrap()
                .map(|utxo| utxo.output().clone()),
        ];
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Try to unmint with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &inputs_utxos_refs,
                0,
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

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureVerificationFailed
                )
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
                &inputs_utxos_refs,
                0,
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

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
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
        let mut tf = make_test_framework_with_v1(&mut rng);
        let token_min_supply_change_fee =
            tf.chainstate.get_chain_config().token_min_supply_change_fee();
        let genesis_block_id = tf.genesis().get_id();

        let (controller_sk, controller_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Lockable,
            reissuance_controller: Destination::PublicKey(controller_pk.clone()),
        });

        let (token_id, _, utxo_with_change) = issue_token_from_block(
            &mut tf,
            genesis_block_id.into(),
            UtxoOutPoint::new(genesis_block_id.into(), 0),
            issuance,
        );

        // Try to lock without signature
        let tx_no_signatures = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::TokenSupplyLock(token_id),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                utxo_with_change.clone().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::Coin(
                token_min_supply_change_fee,
            )))
            .build();

        let result = tf
            .make_block_builder()
            .add_transaction(tx_no_signatures.clone())
            .build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureNotFound
                )
            ))
        );

        let inputs_utxos = vec![
            None,
            tf.chainstate.utxo(&utxo_with_change).unwrap().map(|utxo| utxo.output().clone()),
        ];
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Try to lock with wrong signature
        let tx = {
            let tx = tx_no_signatures.transaction().clone();

            let (some_sk, some_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let account_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &some_sk,
                Default::default(),
                Destination::PublicKey(some_pk),
                &tx,
                &inputs_utxos_refs,
                0,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SignatureVerificationFailed(
                    common::chain::signature::TransactionSigError::SignatureVerificationFailed
                )
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
                &inputs_utxos_refs,
                0,
            )
            .unwrap();

            SignedTransaction::new(
                tx,
                vec![InputWitness::Standard(account_sig), InputWitness::NoSignature(None)],
            )
            .unwrap()
        };

        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
    });
}
