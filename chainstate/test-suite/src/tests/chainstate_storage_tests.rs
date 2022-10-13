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

use super::*;
use chainstate_storage::{inmemory::Store, BlockchainStorageRead, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        tokens::{
            token_id, OutputValue, TokenAuxiliaryData, TokenData, TokenIssuanceV1, TokenTransferV1,
        },
        Destination, OutPoint, OutPointSourceId, SpendablePosition, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use utxo::UtxosStorageRead;

// Process a tx with a coin. Check that new utxo and tx index are stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_coin(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = Store::new_empty().unwrap();
        let mut tf = TestFramework::builder().with_storage(storage.clone()).build();
        let mut rng = make_seedable_rng(seed);

        let tx_output = TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(100)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        );

        // spend coin
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(tx_output.clone())
            .build();
        let tx_id = tx.transaction().get_id();

        let tx_utxo_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_id), 0);

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );

        // tx index is stored
        let tx_index = db_tx
            .get_mainchain_tx_index(&tx_utxo_outpoint.tx_id())
            .expect("ok")
            .expect("some");
        let tx_pos = match tx_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx.get_mainchain_tx_by_position(tx_pos).expect("ok").expect("some").get_id(),
            tx_id
        );

        // utxo is stored
        assert_eq!(
            db_tx.get_utxo(&tx_utxo_outpoint).expect("ok").expect("some").output(),
            &tx_output
        );
        assert_eq!(
            db_tx.get_undo_data(block_id).expect("ok").expect("some").tx_undos().len(),
            1
        );
    });
}

// Process a tx with a token issuance. Check that new token and tx index are stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_token(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = Store::new_empty().unwrap();
        let mut tf = TestFramework::builder().with_storage(storage.clone()).build();
        let mut rng = make_seedable_rng(seed);

        // issue a token
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenIssuanceV1 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let tx_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_id), 0);
        let token_id = token_id(tx.transaction()).unwrap();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build();
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        let db_tx = storage.transaction_ro().unwrap();

        // best block has changed
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );

        // tx index is stored
        let tx_index =
            db_tx.get_mainchain_tx_index(&tx_outpoint.tx_id()).expect("ok").expect("some");
        let tx_pos = match tx_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx.get_mainchain_tx_by_position(tx_pos).expect("ok").expect("some").get_id(),
            tx_id
        );

        // token info is stored
        assert_eq!(
            db_tx.get_token_id(&tx_id).expect("ok").expect("some"),
            token_id
        );
        let aux_data = db_tx.get_token_aux_data(&token_id).expect("ok").expect("some");
        let expected_aux_data = TokenAuxiliaryData::new(tx.transaction().clone(), block_id);
        assert_eq!(aux_data, expected_aux_data);
    });
}

// Create a block '1' with a coin. Check that info is stored in the storage.
// Create alternative chain with 2 blocks, which causes reorg.
// Check that info from the block '1' was removed from the storage and the info from block '2' and '3'
// was written.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_store_coin(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = Store::new_empty().unwrap();
        let mut tf = TestFramework::builder().with_storage(storage.clone()).build();
        let genesis_id = tf.genesis().get_id();
        let mut rng = make_seedable_rng(seed);

        // create block
        let tx_1_output = TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(300)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        );
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_1_output)
            .build();
        let tx_1_utxo_outpoint = OutPoint::new(
            OutPointSourceId::Transaction(tx_1.transaction().get_id()),
            0,
        );

        let block_1 = tf.make_block_builder().add_transaction(tx_1).build();
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();

        // create parallel chain
        let tx_2_output = TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(200)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        );
        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_2_output)
            .build();
        let tx_2_id = tx_2.transaction().get_id();
        let tx_2_utxo_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_2_id), 0);

        let block_2 = tf
            .make_block_builder()
            .add_transaction(tx_2)
            .with_parent(genesis_id.into())
            .build();
        let block_2_id = block_2.get_id();
        tf.process_block(block_2, BlockSource::Local).unwrap();

        // produce one more block to cause reorg
        let tx_3_output = TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(100)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        );
        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx_2_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_3_output.clone())
            .build();
        let tx_3_id = tx_3.transaction().get_id();
        let tx_3_utxo_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_3_id), 0);

        let block_3 = tf
            .make_block_builder()
            .add_transaction(tx_3)
            .with_parent(block_2_id.into())
            .build();
        let block_3_id = block_3.get_id();
        tf.process_block(block_3, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
        );

        // tx index from block_1 was deleted
        assert_eq!(
            db_tx.get_mainchain_tx_index(&tx_1_utxo_outpoint.tx_id()).expect("ok"),
            None
        );
        // tx index from block_2 is stored
        let tx_2_index = db_tx
            .get_mainchain_tx_index(&tx_2_utxo_outpoint.tx_id())
            .expect("ok")
            .expect("some");
        let tx_2_pos = match tx_2_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx
                .get_mainchain_tx_by_position(tx_2_pos)
                .expect("ok")
                .expect("some")
                .get_id(),
            tx_2_id
        );
        // tx index from block_3 is stored
        let tx_3_index = db_tx
            .get_mainchain_tx_index(&tx_3_utxo_outpoint.tx_id())
            .expect("ok")
            .expect("some");
        let tx_3_pos = match tx_3_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx
                .get_mainchain_tx_by_position(tx_3_pos)
                .expect("ok")
                .expect("some")
                .get_id(),
            tx_3_id
        );

        // utxo from block_1 was deleted
        assert_eq!(db_tx.get_utxo(&tx_1_utxo_outpoint).expect("ok"), None);
        assert_eq!(db_tx.get_undo_data(block_1_id).expect("ok"), None);
        // utxo from block_2 was deleted
        assert_eq!(db_tx.get_utxo(&tx_2_utxo_outpoint).expect("ok"), None);
        assert_eq!(
            db_tx.get_undo_data(block_2_id).expect("ok").expect("some").tx_undos().len(),
            1
        );
        // utxo from block_3 is stored
        assert_eq!(
            db_tx.get_utxo(&tx_3_utxo_outpoint).expect("ok").expect("some").output(),
            &tx_3_output
        );
        assert_eq!(
            db_tx.get_undo_data(block_3_id).expect("ok").expect("some").tx_undos().len(),
            1
        );
    });
}

// Create a block '1' with a token. Check that info is stored in the storage.
// Create alternative chain with 2 blocks, which causes reorg.
// Check that info from the block '1' was removed from the storage and the info from block '2' and '3'
// was written.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_store_token(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = Store::new_empty().unwrap();
        let mut tf = TestFramework::builder().with_storage(storage.clone()).build();
        let genesis_id = tf.genesis().get_id();
        let mut rng = make_seedable_rng(seed);

        // create block
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenIssuanceV1 {
                    token_ticker: "AAAA".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();
        let tx_1_outpoint = OutPoint::new(
            OutPointSourceId::Transaction(tx_1.transaction().get_id()),
            0,
        );
        let token_1_id = token_id(tx_1.transaction()).unwrap();
        let tx_1_id = tx_1.transaction().get_id();

        let block_1 = tf.make_block_builder().add_transaction(tx_1).build();
        tf.process_block(block_1, BlockSource::Local).unwrap();

        // create parallel chain
        let bbbb_tokens_amount = Amount::from_atoms(rng.gen_range(1..u128::MAX));
        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenIssuanceV1 {
                    token_ticker: "BBBB".as_bytes().to_vec(),
                    amount_to_issue: bbbb_tokens_amount,
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();
        let tx_2_id = tx_2.transaction().get_id();
        let tx_2_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_2_id), 0);
        let token_2_id = token_id(tx_2.transaction()).unwrap();

        let block_2 = tf
            .make_block_builder()
            .add_transaction(tx_2.clone())
            .with_parent(genesis_id.into())
            .build();
        let block_2_id = block_2.get_id();
        tf.process_block(block_2, BlockSource::Local).unwrap();

        // produce one more block to cause reorg
        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx_2_id), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenData::TokenTransferV1(TokenTransferV1 {
                    token_id: token_2_id,
                    amount: bbbb_tokens_amount,
                })
                .into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();
        let tx_3_id = tx_3.transaction().get_id();
        let tx_3_outpoint = OutPoint::new(OutPointSourceId::Transaction(tx_3_id), 0);
        let token_3_id = token_id(tx_3.transaction()).unwrap();

        let block_3 = tf
            .make_block_builder()
            .add_transaction(tx_3)
            .with_parent(block_2_id.into())
            .build();
        let block_3_id = block_3.get_id();
        tf.process_block(block_3, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
        );

        // tx index from block_1 was deleted
        assert_eq!(
            db_tx.get_mainchain_tx_index(&tx_1_outpoint.tx_id()).expect("ok"),
            None
        );
        // tx index from block_2 is stored
        let tx_2_index =
            db_tx.get_mainchain_tx_index(&tx_2_outpoint.tx_id()).expect("ok").expect("some");
        let tx_2_pos = match tx_2_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx
                .get_mainchain_tx_by_position(tx_2_pos)
                .expect("ok")
                .expect("some")
                .get_id(),
            tx_2_id
        );
        // tx index from block_3 is stored
        let tx_3_index =
            db_tx.get_mainchain_tx_index(&tx_3_outpoint.tx_id()).expect("ok").expect("some");
        let tx_3_pos = match tx_3_index.position() {
            SpendablePosition::Transaction(tx_pos) => tx_pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        assert_eq!(
            db_tx
                .get_mainchain_tx_by_position(tx_3_pos)
                .expect("ok")
                .expect("some")
                .get_id(),
            tx_3_id
        );

        // token info for block_1 is deleted
        assert_eq!(db_tx.get_token_id(&tx_1_id).expect("ok"), None);
        assert_eq!(token_1_id, token_2_id);

        // token issuance from tx block_2 was stored
        assert_eq!(
            db_tx.get_token_id(&tx_2_id).expect("ok").expect("some"),
            token_2_id
        );
        let aux_data_b = db_tx.get_token_aux_data(&token_2_id).expect("ok").expect("some");
        let expected_aux_data_b = TokenAuxiliaryData::new(tx_2.transaction().clone(), block_2_id);
        assert_eq!(aux_data_b, expected_aux_data_b);

        //tx block_3 was Transfer so no data update
        assert_eq!(db_tx.get_token_id(&tx_3_id).expect("ok"), None);
        assert_eq!(db_tx.get_token_aux_data(&token_3_id).expect("ok"), None);
    });
}
