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

use std::vec;

use chainstate::{
    BlockError, BlockSource, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::chain::tokens::{Metadata, NftIssuanceV0, TokenIssuanceV0, TokenTransfer};
use common::chain::UtxoOutPoint;
use common::primitives::{id, BlockHeight, Id};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{make_token_id, TokenData, TokenId},
        Destination, OutPointSourceId, TokenIssuanceVersion, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::hash::StreamHasher;
use expect_test::expect;
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::nft_utils::random_token_issuance;
use test_utils::{
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::CheckTransactionError;

use super::helpers::chainstate_upgrade_builder::ChainstateUpgradeBuilder;

fn make_test_framework_with_v0(rng: &mut (impl Rng + CryptoRng)) -> TestFramework {
    TestFramework::builder(rng)
        .with_chain_config(
            common::chain::config::Builder::test_chain()
                .chainstate_upgrades(
                    common::chain::NetUpgrades::initialize(vec![(
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest()
                            .token_issuance_version(TokenIssuanceVersion::V0)
                            .build(),
                    )])
                    .unwrap(),
                )
                .genesis_unittest(Destination::AnyoneCanSpend)
                .build(),
        )
        .build()
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issue_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        let outpoint_source_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        // Valid case
        let output_value = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(outpoint_source_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(
            get_output_value(&block.transactions()[0].transaction().outputs()[0]).unwrap(),
            output_value.into()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_transfer_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        // To have possibility to send exceed tokens amount than we have, let's limit the max issuance tokens amount
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX - 1));
        let genesis_outpoint_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        // Issue a new token
        let output_value = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: "https://some_site.some".as_bytes().to_vec(),
        };

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();
        assert_eq!(
            get_output_value(&block.transactions()[0].transaction().outputs()[0]).unwrap(),
            output_value.clone().into()
        );
        let issuance_outpoint_id: OutPointSourceId =
            block.transactions()[0].transaction().get_id().into();

        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn multiple_token_issuance_in_one_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let genesis_outpoint_id: OutPointSourceId = tf.genesis().get_id().into();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        // Issue a couple of tokens
        let issuance_value = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };

        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        issuance_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        issuance_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);
        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::CheckTransactionError(
                        CheckTransactionError::TokensError(
                            TokensError::MultipleTokenIssuanceInTransaction(_)
                        )
                    )
                ))
            ))
        ));

        // Valid issuance
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        issuance_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        assert_eq!(
            get_output_value(&block.transactions()[0].transaction().outputs()[0]).unwrap(),
            issuance_value.into()
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_with_insufficient_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let coins_value =
            (get_output_value(&tf.genesis().utxos()[0]).unwrap().coin_amount().unwrap()
                - token_issuance_fee)
                .unwrap();
        let genesis_outpoint_id = tf.genesis().get_id().into();

        // Issuance data
        let issuance_data = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                issuance_data.clone().into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(coins_value),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                (token_issuance_fee - Amount::from_atoms(1)).unwrap(),
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf
            .make_block_builder()
            // All coins in inputs added to outputs, fee = 0 coins
            .add_transaction(tx)
            .build(&mut rng);

        let result = tf.process_block(block, BlockSource::Local);

        // Try to process tx with insufficient token fees
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::InsufficientTokenFees(tx_id))
            ))
        );

        // Valid issuance
        let genesis_outpoint_id = tf.genesis().get_id().into();
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        issuance_data.into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn transfer_split_and_combine_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        // Due to transfer a piece of funds, let's limit the start range value
        let total_funds = Amount::from_atoms(rng.gen_range(4..u128::MAX - 1));
        let quarter_funds = (total_funds / 4).unwrap();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = block.transactions()[0].transaction().get_id().into();
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();

        // Split tokens in outputs
        let split_block = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    // One piece of tokens in the first output, other piece of tokens in the second output
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: (total_funds - quarter_funds).unwrap(),
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: quarter_funds,
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build(&mut rng);
        let split_outpoint_id: OutPointSourceId =
            split_block.transactions()[0].transaction().get_id().into();
        tf.process_block(split_block, BlockSource::Local).unwrap().unwrap();

        // Collect these in one output
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(split_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(split_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_and_try_to_double_spend_tokens(#[case] seed: Seed) {
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
    // B1, check that output is spent.

    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        // Issue a new token
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let issuance_data = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: total_funds,
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        }
        .into();
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(genesis_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        issuance_data,
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(token_issuance_fee),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let issuance_outpoint_id: OutPointSourceId =
            issuance_block.transactions()[0].transaction().get_id().into();
        let token_id =
            make_token_id(issuance_block.transactions()[0].transaction().inputs()).unwrap();

        // B1 - burn all tokens in mainchain
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id.clone(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block_b1 = tf.block(*block_index.block_id());
        let b1_outpoint_id: OutPointSourceId =
            block_b1.transactions()[0].transaction().get_id().into();

        // Try to transfer burnt tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(b1_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(UtxoOutPoint::new(
                    b1_outpoint_id.clone(),
                    0
                ))
            ))
        );

        // Let's add C1
        let output_value = OutputValue::Coin(Amount::from_atoms(123453));
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(b1_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value.clone(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block_c1 = tf.block(*block_index.block_id());
        let c1_outpoint_id: OutPointSourceId =
            block_c1.transactions()[0].transaction().get_id().into();
        // Let's add D1
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(c1_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        output_value,
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block_d1 = tf.block(*block_index.block_id());
        let _: OutPointSourceId = block_d1.transactions()[0].transaction().get_id().into();

        // Second chain - B2
        let block_b2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: total_funds,
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build(&mut rng);
        let b2_outpoint_id: OutPointSourceId =
            block_b2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_b2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // C2 - burn all tokens in a second chain
        let block_c2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(b2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(b2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build(&mut rng);
        let c2_outpoint_id: OutPointSourceId =
            block_c2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_c2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // Now D2 trying to spend tokens from mainchain
        let block_d2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(c2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(c2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(
                        TokenTransfer {
                            token_id,
                            amount: total_funds,
                        }
                        .into(),
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123454)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build(&mut rng);
        let d2_outpoint_id: OutPointSourceId =
            block_d2.transactions()[0].transaction().get_id().into();
        assert!(
            tf.process_block(block_d2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // Block E2 will cause reorganization
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(d2_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_input(
                        TxInput::from_utxo(d2_outpoint_id.clone(), 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123453)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(UtxoOutPoint::new(d2_outpoint_id, 0))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_issuance_in_block_reward(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);
        let total_funds = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let (_, pub_key) =
            crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);

        // Check if it issuance
        let reward_output = TxOutput::Transfer(
            TokenIssuanceV0 {
                token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
                amount_to_issue: total_funds,
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024)
                    .as_bytes()
                    .to_vec(),
            }
            .into(),
            Destination::PublicKey(pub_key.clone()),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it transfer
        let reward_output = TxOutput::Transfer(
            TokenData::TokenTransfer(TokenTransfer {
                token_id: TokenId::random_using(&mut rng),
                amount: total_funds,
            })
            .into(),
            Destination::PublicKey(pub_key),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Check if it burn
        let reward_output = TxOutput::Burn(
            TokenTransfer {
                token_id: TokenId::random_using(&mut rng),
                amount: total_funds,
            }
            .into(),
        );
        let block = tf
            .make_block_builder()
            .with_reward(vec![reward_output])
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));
    })
}

#[test]
fn chosen_hashes_for_token_data() {
    // If fields order of TokenData accidentally will be changed, snapshots cause fail
    let mut hash_stream = id::DefaultHashAlgoStream::new();

    // Token issuance
    let token_issuance = TokenIssuanceV0 {
        token_ticker: b"SOME".to_vec(),
        amount_to_issue: Amount::from_atoms(123456789),
        number_of_decimals: 123,
        metadata_uri: "https://some_site.some".as_bytes().to_vec(),
    };
    id::hash_encoded_to(&token_issuance, &mut hash_stream);
    expect![[r#"
            0x4ee0ff57394428ef6d740e9634bf8a10caed48e6b8a2ba9630f46f14e44a3aa6
        "#]]
    .assert_debug_eq(&Id::<TokenIssuanceV0>::new(hash_stream.finalize().into()).to_hash());

    // NFT issuance
    let nft_issuance = NftIssuanceV0 {
        metadata: Metadata {
            creator: None,
            name: b"SOME".to_vec(),
            description: b"NFT".to_vec(),
            ticker: b"Ticker".to_vec(),
            icon_uri: DataOrNoVec::from(Some(vec![9, 8, 7, 6, 5, 4, 3, 2, 1])),
            additional_metadata_uri: DataOrNoVec::from(Some(vec![
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ])),
            media_uri: DataOrNoVec::from(Some(vec![20, 21, 22, 23, 24, 25, 26, 27, 28, 29])),
            media_hash: vec![30, 31, 32, 33, 34, 35, 36, 37, 38, 39],
        },
    };
    id::hash_encoded_to(&nft_issuance, &mut hash_stream);
    expect![[r#"
            0x5ab12d01286027603a6483405b9a970c094c16f3f51be2fa98f8c936edd76abe
        "#]]
    .assert_debug_eq(&Id::<NftIssuanceV0>::new(hash_stream.finalize().into()).to_hash());

    // Token Transfer
    let token_data = TokenData::TokenTransfer(TokenTransfer {
        token_id: TokenId::zero(),
        amount: Amount::from_atoms(1234567890),
    });
    id::hash_encoded_to(&token_data, &mut hash_stream);
    expect![[r#"
            0x4f4de86926d24333f82952bf98c170f37b4c53b9c2249c607d30fd34c0b68f98
        "#]]
    .assert_debug_eq(&Id::<TokenData>::new(hash_stream.finalize().into()).to_hash());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_and_transfer_in_the_same_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework_with_v0(&mut rng);

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenIssuanceV0 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(100_000..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id: make_token_id(tx_1.transaction().inputs()).unwrap(),
                    amount: Amount::from_atoms(rng.gen_range(1..100_000)),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_v0_issuance_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .token_issuance_version(TokenIssuanceVersion::V1)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_token_issuance(tf.chain_config(), &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::DeprecatedTokenOperationVersion(
                            TokenIssuanceVersion::V0,
                            tx_id,
                        )
                    )
                )
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_v0_transfer_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .token_issuance_version(TokenIssuanceVersion::V0)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(2),
                                ChainstateUpgradeBuilder::latest()
                                    .token_issuance_version(TokenIssuanceVersion::V1)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

        let tx_with_issuance = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_token_issuance(tf.chain_config(), &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_with_issuance_id = tx_with_issuance.transaction().get_id();
        let token_id = make_token_id(tx_with_issuance.inputs()).unwrap();

        tf.make_block_builder()
            .add_transaction(tx_with_issuance)
            .build_and_process(&mut rng)
            .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx_with_issuance_id), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id,
                    amount: Amount::from_atoms(1),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::DeprecatedTokenOperationVersion(
                            TokenIssuanceVersion::V0,
                            tx_id,
                        )
                    )
                )
            ))
        );
    })
}
