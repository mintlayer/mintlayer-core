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

use std::collections::BTreeMap;

use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TestStore, TransactionBuilder,
};
use common::{
    chain::{
        make_token_id,
        output_value::OutputValue,
        tokens::{NftIssuance, TokenAuxiliaryData, TokenId, TokenIssuanceV0},
        ChainstateUpgradeBuilder, Destination, OutPointSourceId, TokenIssuanceVersion, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Id, Idable},
};
use test_utils::nft_utils::random_nft_issuance;
use utxo::{Utxo, UtxosStorageRead, UtxosTxUndo};

use super::*;

// Process a tx with a coin. Check that new utxo and tx index are stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_coin(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_storage(storage.clone()).build();

        let tx_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            anyonecanspend_address(),
        );

        // spend coin
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(tx_output.clone())
            .build();
        let tx_id = tx.transaction().get_id();

        let tx_utxo_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0);

        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok"),
            Id::<GenBlock>::from(block_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );

        // utxo is stored
        assert_eq!(
            db_tx.get_utxo(&tx_utxo_outpoint).expect("ok").expect("some").output(),
            &tx_output
        );

        let expected_undo_utxo_data: BTreeMap<Id<Transaction>, UtxosTxUndo> = [(
            tx_id,
            UtxosTxUndo::new(vec![Some(Utxo::new_for_blockchain(
                tf.genesis().utxos().first().unwrap().clone(),
                BlockHeight::zero(),
            ))]),
        )]
        .into();

        assert_eq!(
            *db_tx.get_undo_data(block_id).expect("ok").expect("some").tx_undos(),
            expected_undo_utxo_data
        );
    });
}

// Process a tx with a token issuance v0. Check that token and tx index is not stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_fungible_token_v0(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
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
            .build();

        // issue a token
        let tx = TransactionBuilder::new()
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
                    amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }
                .into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().fungible_token_issuance_fee(),
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            BlockHeight::zero(),
            tx.transaction().inputs(),
        )
        .unwrap();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        let db_tx = storage.transaction_ro().unwrap();

        // best block has changed
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok"),
            Id::<GenBlock>::from(block_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );

        // token info is not stored
        assert!(db_tx.get_token_id(&tx_id).unwrap().is_none());
        assert!(db_tx.get_token_aux_data(&token_id).unwrap().is_none());
        // but utxo is there
        assert!(db_tx.get_utxo(&UtxoOutPoint::new(tx_id.into(), 0)).unwrap().is_some());
    });
}

// Process a tx with a token issuance v0. Check that token and tx index is not stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_nft_v0(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
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
            .build();

        // issue a token
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_nft_issuance(tf.chainstate.get_chain_config(), &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().fungible_token_issuance_fee(),
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            BlockHeight::zero(),
            tx.transaction().inputs(),
        )
        .unwrap();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        let db_tx = storage.transaction_ro().unwrap();

        // best block has changed
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok"),
            Id::<GenBlock>::from(block_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_id)
        );

        // token info is not stored
        assert!(db_tx.get_token_id(&tx_id).unwrap().is_none());
        assert!(db_tx.get_token_aux_data(&token_id).unwrap().is_none());
        // but utxo is there
        assert!(db_tx.get_utxo(&UtxoOutPoint::new(tx_id.into(), 0)).unwrap().is_some());
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
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_storage(storage.clone()).build();
        let genesis_id = tf.genesis().get_id();

        // create block
        let tx_1_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(300)),
            anyonecanspend_address(),
        );
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_1_output)
            .build();
        let tx_1_utxo_outpoint = UtxoOutPoint::new(
            OutPointSourceId::Transaction(tx_1.transaction().get_id()),
            0,
        );

        let block_1 = tf.make_block_builder().add_transaction(tx_1).build(&mut rng);
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();

        // create parallel chain
        let tx_2_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(200)),
            anyonecanspend_address(),
        );
        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_2_output)
            .build();
        let tx_2_id = tx_2.transaction().get_id();
        let tx_2_utxo_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_2_id), 0);

        let block_2 = tf
            .make_block_builder()
            .add_transaction(tx_2)
            .with_parent(genesis_id.into())
            .build(&mut rng);
        let block_2_id = block_2.get_id();
        tf.process_block(block_2, BlockSource::Local).unwrap();

        // produce one more block to cause reorg
        let tx_3_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            anyonecanspend_address(),
        );
        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx_2_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_3_output.clone())
            .build();
        let tx_3_id = tx_3.transaction().get_id();
        let tx_3_utxo_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_3_id), 0);

        let block_3 = tf
            .make_block_builder()
            .add_transaction(tx_3)
            .with_parent(block_2_id.into())
            .build(&mut rng);
        let block_3_id = block_3.get_id();
        tf.process_block(block_3, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok"),
            Id::<GenBlock>::from(block_3_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
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

// Create Test framework with disposable strategy.
// Create a block '1' which spends coins in 2 txs. Check that info is stored in the storage.
// Create alternative chain with 2 blocks, which causes reorg.
// Check that info from the block '1' was removed from the storage and the info from block '2' and '3'
// was written.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reorg_store_coin_disposable(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = TestStore::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_tx_verification_strategy(
                chainstate_test_framework::TxVerificationStrategy::Disposable,
            )
            .build();
        let genesis_id = tf.genesis().get_id();

        // create block
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(300)),
                anyonecanspend_address(),
            ))
            .build();
        let tx_1_utxo_outpoint = UtxoOutPoint::new(
            OutPointSourceId::Transaction(tx_1.transaction().get_id()),
            0,
        );

        let tx_1_2 = TransactionBuilder::new()
            .add_input(tx_1_utxo_outpoint.clone().into(), empty_witness(&mut rng))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(300)),
                anyonecanspend_address(),
            ))
            .build();

        let block_1 = tf.make_block_builder().with_transactions(vec![tx_1, tx_1_2]).build(&mut rng);
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();

        // create parallel chain
        let tx_2_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(200)),
            anyonecanspend_address(),
        );
        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_2_output)
            .build();
        let tx_2_id = tx_2.transaction().get_id();
        let tx_2_utxo_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_2_id), 0);

        let block_2 = tf
            .make_block_builder()
            .add_transaction(tx_2)
            .with_parent(genesis_id.into())
            .build(&mut rng);
        let block_2_id = block_2.get_id();
        tf.process_block(block_2, BlockSource::Local).unwrap();

        // produce one more block to cause reorg
        let tx_3_output = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            anyonecanspend_address(),
        );
        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(tx_2_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(tx_3_output.clone())
            .build();
        let tx_3_id = tx_3.transaction().get_id();
        let tx_3_utxo_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_3_id), 0);

        let block_3 = tf
            .make_block_builder()
            .add_transaction(tx_3)
            .with_parent(block_2_id.into())
            .build(&mut rng);
        let block_3_id = block_3.get_id();
        tf.process_block(block_3, BlockSource::Local).unwrap();

        // best block has changed
        let db_tx = storage.transaction_ro().unwrap();
        assert_eq!(
            db_tx.get_best_block_for_utxos().expect("ok"),
            Id::<GenBlock>::from(block_3_id)
        );
        assert_eq!(
            db_tx.get_best_block_id().expect("ok").expect("some"),
            Id::<GenBlock>::from(block_3_id)
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

// Process a tx with a nft issuance. Check that new token and tx index are stored, best block is updated.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn store_aux_data_from_issue_nft(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_id = TokenId::from_utxo(&UtxoOutPoint::new(tf.genesis().get_id().into(), 0));

        // issue a token
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(random_nft_issuance(
                    tf.chainstate.get_chain_config(),
                    &mut rng,
                ))),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(
                tf.chainstate.get_chain_config().fungible_token_issuance_fee(),
            )))
            .build();
        let tx_id = tx.transaction().get_id();

        let block = tf.make_block_builder().add_transaction(tx.clone()).build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();

        let db_tx = tf.storage.transaction_ro().unwrap();

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
