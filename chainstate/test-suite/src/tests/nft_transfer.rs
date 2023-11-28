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

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, IOPolicyError, TokensError,
};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::primitives::Idable;
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{
            make_token_id, Metadata, NftIssuance, NftIssuanceV0, TokenData, TokenId,
            TokenIssuanceVersion, TokenTransfer,
        },
        ChainstateUpgrade, Destination, NetUpgrades, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::random::Rng;
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::nft_utils::random_nft_issuance;
use test_utils::{
    nft_utils::random_creator,
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::transaction_verifier::CoinOrTokenId;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_transfer_wrong_id(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                output_value.clone().into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        assert_eq!(
            get_output_value(&block.transactions()[0].outputs()[0]).unwrap(),
            output_value.into()
        );
        assert!(tf
            .outputs_from_genblock(block.get_id().into())
            .contains_key(&issuance_outpoint_id));

        // Try to transfer NFT with wrong ID
        let random_token_id = TokenId::random_using(&mut rng);
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id: random_token_id,
                    amount: Amount::from_atoms(1),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(random_token_id)
                    ),
                    tx_id.into()
                )
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_invalid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                output_value.clone().into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx.clone())
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();
        assert_eq!(block.transactions()[0], tx);
        assert_eq!(
            get_output_value(&tx.outputs()[0]).unwrap(),
            output_value.into()
        );

        // Try to transfer 0 NFT
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(0),
                        })
                        .into(),
                        Destination::AnyoneCanSpend,
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

        // Try to transfer more NFT than we have in input
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id,
                    amount: Amount::from_atoms(rng.gen_range(2..123)),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_different_nft_than_one_in_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Issuance a few different NFT
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let output_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }
        .into();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                output_value,
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_min_issuance_fee * 2).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let first_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let first_token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(first_issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(first_issuance_outpoint_id, 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id: first_token_id,
                    amount: Amount::from_atoms(1),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                NftIssuanceV0 {
                    metadata: Metadata {
                        creator: Some(random_creator(&mut rng)),
                        name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len)
                            .into_bytes(),
                        description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                            .into_bytes(),
                        ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len)
                            .into_bytes(),
                        icon_uri: DataOrNoVec::from(None),
                        additional_metadata_uri: DataOrNoVec::from(None),
                        media_uri: DataOrNoVec::from(None),
                        media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                    },
                }
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let second_issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let _ = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();

        // Try to spend 2 NFTs but use one ID

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id.clone(), 1),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(second_issuance_outpoint_id, 2),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id: first_token_id,
                    amount: Amount::from_atoms(2),
                })
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_min_issuance_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(first_token_id)
                    ),
                    tx_id.into()
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_valid_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();
        // Issue a new NFT
        let output_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                output_value.clone().into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();
        assert_eq!(
            get_output_value(&block.transactions()[0].outputs()[0]).unwrap(),
            output_value.into()
        );

        // Valid case
        let transfer_value = TokenData::TokenTransfer(TokenTransfer {
            token_id,
            amount: Amount::from_atoms(1),
        });
        let block_index = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        transfer_value.clone().into(),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(block_index.block_height(), BlockHeight::from(2));

        let block = tf.block(*block_index.block_id());
        let outputs =
            tf.outputs_from_genblock(block.get_id().into()).values().next().unwrap().clone();
        let transfer_output = &outputs[0];

        assert_eq!(
            get_output_value(transfer_output).unwrap(),
            transfer_value.into()
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ensure_nft_cannot_be_printed_from_tokens_op(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
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
            .build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let token_id =
            make_token_id(&[TxInput::from_utxo(genesis_outpoint_id.clone(), 0)]).unwrap();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        let nft_issuance = random_nft_issuance(tf.chainstate.get_chain_config(), &mut rng);

        // Issue
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(nft_issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        // Try print Nfts on transfer
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Transfer
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap();
    })
}
