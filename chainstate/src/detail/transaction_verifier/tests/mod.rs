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

use std::sync::Arc;

use super::*;

use common::{
    chain::{
        config::Builder as ConfigBuilder, tokens::TokenAuxiliaryData, Destination, OutPoint,
        OutputPurpose, TxMainChainIndex, TxMainChainPosition,
    },
    primitives::amount::UnsignedIntType,
};
use crypto::key::{KeyKind, PrivateKey};
use mockall::predicate;
use utxo::UtxosStorageRead;

mod mock;

fn create_utxo(value: UnsignedIntType) -> (OutPoint, Utxo) {
    let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::random())), 0);
    let (_, pub_key1) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let output1 = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(value)),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key1)),
    );
    let utxo = Utxo::new_for_blockchain(output1, false, BlockHeight::new(1));
    (outpoint, utxo)
}

#[test]
fn hierarchy_test_utxo() {
    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint0 = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::random())), 0);
    let block_undo_id_0: Id<Block> = Id::new(H256::random());

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_get_utxo()
        .with(predicate::eq(outpoint0.clone()))
        .times(1)
        .return_const(Ok(None));
    store
        .expect_get_undo_data()
        .with(predicate::eq(block_undo_id_0.clone()))
        .times(1)
        .return_const(Ok(None));

    let (outpoint1, utxo1) = create_utxo(1000);
    let block_undo_id_1: Id<Block> = Id::new(H256::random());
    let (_, utxo1_undo) = create_utxo(100);
    let block_undo_1 = BlockUndo::new(None, vec![TxUndo::new(vec![utxo1_undo])]);

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.utxo_cache.add_utxo(&outpoint1, utxo1.clone(), false).unwrap();
        verifier.utxo_block_undo.insert(
            block_undo_id_1,
            BlockUndoEntry {
                undo: block_undo_1.clone(),
                is_fresh: true,
            },
        );
        verifier
    };

    let (outpoint2, utxo2) = create_utxo(2000);
    let block_undo_id_2: Id<Block> = Id::new(H256::random());
    let (_, utxo1_undo) = create_utxo(100);
    let block_undo_2 = BlockUndo::new(None, vec![TxUndo::new(vec![utxo1_undo])]);

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.utxo_cache.add_utxo(&outpoint2, utxo2.clone(), false).unwrap();
        verifier.utxo_block_undo.insert(
            block_undo_id_2,
            BlockUndoEntry {
                undo: block_undo_2.clone(),
                is_fresh: true,
            },
        );
        verifier
    };

    assert_eq!(
        verifier1.get_utxo(&outpoint1).unwrap().as_ref(),
        Some(&utxo1)
    );
    assert_eq!(
        verifier2.get_utxo(&outpoint2).unwrap().as_ref(),
        Some(&utxo2)
    );
    assert_eq!(
        verifier2.get_utxo(&outpoint1).unwrap().as_ref(),
        Some(&utxo1)
    );
    assert_eq!(verifier2.get_utxo(&outpoint0).unwrap(), None);

    assert_eq!(
        verifier1.get_undo_data(block_undo_id_1).unwrap().as_ref(),
        Some(&block_undo_1)
    );
    assert_eq!(
        verifier2.get_undo_data(block_undo_id_2).unwrap().as_ref(),
        Some(&block_undo_2)
    );
    assert_eq!(
        verifier2.get_undo_data(block_undo_id_1).unwrap().as_ref(),
        Some(&block_undo_1)
    );
    assert_eq!(verifier2.get_undo_data(block_undo_id_0).unwrap(), None);
}

#[test]
fn hierarchy_test_tx_index() {
    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint0 = OutPointSourceId::Transaction(Id::new(H256::zero()));

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_get_mainchain_tx_index()
        .with(predicate::eq(outpoint0.clone()))
        .times(1)
        .return_const(Ok(None));

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random()));
    let pos1 = TxMainChainPosition::new(H256::from_low_u64_be(1).into(), 1).into();
    let tx_index_1 = TxMainChainIndex::new(pos1, 1).unwrap();

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
            outpoint1.clone(),
            CachedInputsOperation::Read(tx_index_1.clone()),
        )]));
        verifier
    };

    let outpoint2 = OutPointSourceId::Transaction(Id::new(H256::random()));
    let pos2 = TxMainChainPosition::new(H256::from_low_u64_be(2).into(), 1).into();
    let tx_index_2 = TxMainChainIndex::new(pos2, 2).unwrap();

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
            outpoint2.clone(),
            CachedInputsOperation::Read(tx_index_2.clone()),
        )]));
        verifier
    };

    assert_eq!(
        verifier1.get_mainchain_tx_index(&outpoint1).unwrap().as_ref(),
        Some(&tx_index_1)
    );

    assert_eq!(
        verifier2.get_mainchain_tx_index(&outpoint2).unwrap(),
        Some(tx_index_2)
    );

    assert_eq!(
        verifier2.get_mainchain_tx_index(&outpoint1).unwrap(),
        Some(tx_index_1)
    );

    assert_eq!(verifier2.get_mainchain_tx_index(&outpoint0).unwrap(), None);
}

#[test]
fn hierarchy_test_tokens() {
    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_0 = H256::random();
    let tx_id_0: Id<Transaction> = Id::new(H256::random());
    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_get_token_aux_data()
        .with(predicate::eq(token_id_0.clone()))
        .times(1)
        .return_const(Ok(None));
    store
        .expect_get_token_id_from_issuance_tx()
        .with(predicate::eq(tx_id_0.clone()))
        .times(1)
        .return_const(Ok(None));

    let token_id_1 = H256::random();
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![], 1).unwrap(),
        Id::new(H256::random()),
    );
    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(
                token_id_1,
                CachedTokensOperation::Write(token_data_1.clone()),
            )]),
            BTreeMap::from([(token_data_1.issuance_tx().get_id(), token_id_1)]),
        );
        verifier
    };

    let token_id_2 = H256::random();
    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![], 2).unwrap(),
        Id::new(H256::random()),
    );
    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(
                token_id_2,
                CachedTokensOperation::Read(token_data_2.clone()),
            )]),
            BTreeMap::from([(token_data_2.issuance_tx().get_id(), token_id_2)]),
        );
        verifier
    };

    assert_eq!(
        verifier1.get_token_aux_data(&token_id_1).unwrap().as_ref(),
        Some(&token_data_1)
    );
    assert_eq!(
        verifier2.get_token_aux_data(&token_id_1).unwrap().as_ref(),
        Some(&token_data_1)
    );
    assert_eq!(
        verifier2.get_token_aux_data(&token_id_2).unwrap().as_ref(),
        Some(&token_data_2)
    );
    assert_eq!(verifier2.get_token_aux_data(&token_id_0).unwrap(), None);

    assert_eq!(
        verifier1
            .get_token_id_from_issuance_tx(token_data_1.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_1)
    );
    assert_eq!(
        verifier2
            .get_token_id_from_issuance_tx(token_data_1.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_1)
    );
    assert_eq!(
        verifier2
            .get_token_id_from_issuance_tx(token_data_2.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_2)
    );
    assert_eq!(
        verifier2.get_token_id_from_issuance_tx(tx_id_0).unwrap(),
        None
    );
}

#[test]
fn hierarchy_test_ancestor() {
    let chain_config = ConfigBuilder::test_chain().build();

    let ancestor = GenBlockIndex::Genesis(Arc::clone(chain_config.genesis_block()));
    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_get_ancestor().times(1).return_const(Ok(ancestor));

    let verifier = TransactionVerifier::new(&store, &chain_config);
    let block_index = GenBlockIndex::Genesis(Arc::clone(chain_config.genesis_block()));
    verifier.get_ancestor(&block_index, BlockHeight::one()).unwrap();
}

#[test]
fn hierarchy_test_block_index() {
    let chain_config = ConfigBuilder::test_chain().build();

    let block_id: Id<Block> = Id::new(H256::random());
    let block_index = GenBlockIndex::Genesis(Arc::clone(chain_config.genesis_block()));
    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_get_gen_block_index().times(1).return_const(Ok(Some(block_index)));

    let verifier = TransactionVerifier::new(&store, &chain_config);
    verifier.get_gen_block_index(&block_id.into()).unwrap();
}
