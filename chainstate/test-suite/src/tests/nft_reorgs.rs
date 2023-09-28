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

use chainstate::{BlockError, BlockSource, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{make_token_id, Metadata, NftIssuanceV0, TokenData, TokenTransfer},
        Destination, OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Idable},
};
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    nft_utils::random_creator,
    random::{make_seedable_rng, Seed},
    random_string,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_and_try_to_double_spend_nfts(#[case] seed: Seed) {
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
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut rng = make_seedable_rng(seed);

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Issue a new NFT
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let issuance_data = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        }
        .into();
        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

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
                        OutputValue::Coin(token_min_issuance_fee),
                        Destination::AnyoneCanSpend,
                    ))
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let issuance_outpoint_id = tf
            .outputs_from_genblock(issuance_block.get_id().into())
            .keys()
            .next()
            .unwrap()
            .clone();
        let token_id =
            make_token_id(issuance_block.transactions()[0].transaction().inputs()).unwrap();

        // B1 - burn NFT in mainchain
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
                            amount: Amount::from_atoms(1),
                        }
                        .into(),
                    ))
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123455)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_b1 = tf.block(*block_index.block_id());
        let b1_outpoint_id = tf
            .outputs_from_genblock(block_b1.get_id().into())
            .keys()
            .next()
            .unwrap()
            .clone();

        // Try to transfer burnt NFT
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
                            amount: Amount::from_atoms(1),
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
            .build_and_process();

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
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_c1 = tf.block(*block_index.block_id());
        let c1_outpoint_id = tf
            .outputs_from_genblock(block_c1.get_id().into())
            .keys()
            .next()
            .unwrap()
            .clone();
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
            .build_and_process()
            .unwrap()
            .unwrap();
        let block_d1 = tf.block(*block_index.block_id());
        let _ = tf
            .outputs_from_genblock(block_d1.get_id().into())
            .keys()
            .next()
            .unwrap()
            .clone();

        // Second chain - B2
        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id, 0),
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
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(123454)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let b2_outpoint_id: OutPointSourceId = tx_2.transaction().get_id().into();
        let block_b2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(tx_2)
            .build();
        assert!(
            tf.process_block(block_b2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // C2 - burn NFT in a second chain
        let tx_2 = TransactionBuilder::new()
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
                    amount: Amount::from_atoms(1),
                }
                .into(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(123454)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let c2_outpoint_id: OutPointSourceId = tx_2.transaction().get_id().into();
        let block_c2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(tx_2)
            .build();
        assert!(
            tf.process_block(block_c2, BlockSource::Local).unwrap().is_none(),
            "Reorg shouldn't have happened yet"
        );

        // Now D2 trying to spend NFT from mainchain
        let tx_2 = TransactionBuilder::new()
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
                    amount: Amount::from_atoms(1),
                }
                .into(),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(123454)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let d2_outpoint_id: OutPointSourceId = tx_2.transaction().get_id().into();
        let block_d2 = tf
            .make_block_builder()
            .with_parent(issuance_block.get_id().into())
            .add_transaction(tx_2)
            .build();
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
                        TxInput::from_utxo(d2_outpoint_id, 1),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(123453)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::MissingOutputOrSpent(_))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_reorgs_and_cleanup_data(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        let token_min_issuance_fee = tf.chainstate.get_chain_config().token_min_issuance_fee();

        // Issue a new NFT
        let issuance_value = NftIssuanceV0 {
            metadata: Metadata {
                creator: Some(random_creator(&mut rng)),
                name: random_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_string(&mut rng, 1..max_desc_len).into_bytes(),
                ticker: random_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let genesis_id = tf.genesis().get_id();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let block_index = tf
            .make_block_builder()
            .with_parent(genesis_id.into())
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
                    .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
                    .build(),
            )
            .build_and_process()
            .unwrap()
            .unwrap();

        let issuance_block = tf.block(*block_index.block_id());
        let token_id =
            make_token_id(issuance_block.transactions()[0].transaction().inputs()).unwrap();

        // Check NFT available in storage
        let token_aux_data = tf.chainstate.get_token_aux_data(token_id).unwrap().unwrap();
        // Check id
        assert_eq!(issuance_block.get_id(), token_aux_data.issuance_block_id());
        let issuance_tx = &issuance_block.transactions()[0];
        assert_eq!(
            issuance_tx.transaction().get_id(),
            token_aux_data.issuance_tx().get_id()
        );
        // Check issuance storage in the chain and in the storage
        assert_eq!(
            get_output_value(&issuance_tx.outputs()[0]).unwrap(),
            issuance_value.clone().into()
        );
        assert_eq!(
            get_output_value(&token_aux_data.issuance_tx().outputs()[0]).unwrap(),
            issuance_value.into()
        );

        // Cause reorg
        tf.create_chain(&tf.genesis().get_id().into(), 5, &mut rng).unwrap();

        // Check that reorg happened
        let height = block_index.block_height();
        assert!(
            tf.chainstate.get_block_id_from_height(&height).unwrap().map_or(false, |id| &id
                .classify(tf.chainstate.get_chain_config())
                .chain_block_id()
                .unwrap()
                != block_index.block_id())
        );

        // Check that issuance transaction in the storage is removed
        assert!(tf
            .chainstate
            .get_mainchain_tx_index(&OutPointSourceId::Transaction(
                issuance_tx.transaction().get_id()
            ))
            .unwrap()
            .is_none());

        // Check that tokens not in storage
        assert!(tf
            .chainstate
            .get_token_id_from_issuance_tx(&issuance_tx.transaction().get_id())
            .unwrap()
            .is_none());

        assert!(tf.chainstate.get_token_info_for_rpc(token_id).unwrap().is_none());

        assert!(tf.chainstate.get_token_aux_data(token_id).unwrap().is_none());
    })
}
