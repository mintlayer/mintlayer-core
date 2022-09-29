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
use crate::detail::transaction_verifier::token_issuance_cache::{
    CachedAuxDataOp, CachedTokenIndexOp,
};
use common::chain::{
    config::Builder as ConfigBuilder, tokens::TokenAuxiliaryData, TxMainChainIndex,
    TxMainChainPosition,
};
use mockall::predicate::eq;

// TODO: ConsumedUtxoCache is not checked in these tests, think how to expose it from utxo crate
// FIXME: test conflicting flushes with errors?

#[test]
fn utxo_set_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(1000);
    let block_1_id: Id<Block> = Id::new(H256::random());
    let block_1_undo = BlockUndo::new(None, vec![TxUndo::new(vec![create_utxo(100).1])]);

    let (outpoint2, utxo2) = create_utxo(2000);
    let block_2_id: Id<Block> = Id::new(H256::random());
    let block_2_undo = BlockUndo::new(None, vec![TxUndo::new(vec![create_utxo(100).1])]);

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_set_undo_data()
        .with(eq(block_1_id), eq(block_1_undo.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_undo_data()
        .with(eq(block_2_id), eq(block_2_undo.clone()))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_cache.add_utxo(&outpoint1, utxo1.clone(), false).unwrap();
    verifier1.utxo_block_undo.insert(
        block_1_id,
        BlockUndoEntry {
            undo: block_1_undo.clone(),
            is_fresh: true,
        },
    );

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.utxo_cache.add_utxo(&outpoint2, utxo2.clone(), false).unwrap();
        verifier.utxo_block_undo.insert(
            block_2_id,
            BlockUndoEntry {
                undo: block_2_undo.clone(),
                is_fresh: true,
            },
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn tx_index_set_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random()));
    let pos1 = TxMainChainPosition::new(H256::from_low_u64_be(1).into(), 1).into();
    let tx_index_1 = TxMainChainIndex::new(pos1, 1).unwrap();

    let outpoint2 = OutPointSourceId::Transaction(Id::new(H256::random()));
    let pos2 = TxMainChainPosition::new(H256::from_low_u64_be(2).into(), 1).into();
    let tx_index_2 = TxMainChainIndex::new(pos2, 2).unwrap();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_set_mainchain_tx_index()
        .with(eq(outpoint1.clone()), eq(tx_index_1.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_mainchain_tx_index()
        .with(eq(outpoint2.clone()), eq(tx_index_2.clone()))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
        outpoint1.clone(),
        CachedInputsOperation::Write(tx_index_1.clone()),
    )]));

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
            outpoint2.clone(),
            CachedInputsOperation::Write(tx_index_2.clone()),
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn tokens_set_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_1 = H256::random();
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![], 1).unwrap(),
        Id::new(H256::random()),
    );

    let token_id_2 = H256::random();
    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![], 2).unwrap(),
        Id::new(H256::random()),
    );

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_set_token_aux_data()
        .with(eq(token_id_1), eq(token_data_1.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_token_aux_data()
        .with(eq(token_id_2), eq(token_data_2.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_token_id()
        .with(eq(token_data_1.issuance_tx().get_id()), eq(token_id_1))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_token_id()
        .with(eq(token_data_2.issuance_tx().get_id()), eq(token_id_2))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.token_issuance_cache = TokenIssuanceCache::new_for_test(
        BTreeMap::from([(token_id_1, CachedAuxDataOp::Write(token_data_1.clone()))]),
        BTreeMap::from([(
            token_data_1.issuance_tx().get_id(),
            CachedTokenIndexOp::Write(token_id_1),
        )]),
    );

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(token_id_2, CachedAuxDataOp::Write(token_data_2.clone()))]),
            BTreeMap::from([(
                token_data_2.issuance_tx().get_id(),
                CachedTokenIndexOp::Write(token_id_2),
            )]),
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn utxo_del_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(1000);
    let block_1_id: Id<Block> = Id::new(H256::random());
    let block_1_undo: BlockUndo = Default::default();

    let (outpoint2, utxo2) = create_utxo(2000);
    let block_2_id: Id<Block> = Id::new(H256::random());
    let block_2_undo: BlockUndo = Default::default();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_get_utxo()
        .with(eq(outpoint1.clone()))
        .times(1)
        .return_const(Ok(Some(utxo1.clone())));
    store
        .expect_get_utxo()
        .with(eq(outpoint2.clone()))
        .times(1)
        .return_const(Ok(Some(utxo2.clone())));

    store.expect_del_undo_data().with(eq(block_1_id)).times(1).return_const(Ok(()));
    store.expect_del_undo_data().with(eq(block_2_id)).times(1).return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_cache.spend_utxo(&outpoint1).unwrap();
    verifier1.utxo_block_undo.insert(
        block_1_id,
        BlockUndoEntry {
            undo: block_1_undo.clone(),
            is_fresh: false,
        },
    );

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.utxo_cache.spend_utxo(&outpoint2).unwrap();
        verifier.utxo_block_undo.insert(
            block_2_id,
            BlockUndoEntry {
                undo: block_2_undo.clone(),
                is_fresh: false,
            },
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn tx_index_del_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random()));
    let outpoint2 = OutPointSourceId::Transaction(Id::new(H256::random()));

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_del_mainchain_tx_index()
        .with(eq(outpoint1.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_mainchain_tx_index()
        .with(eq(outpoint2.clone()))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
        outpoint1.clone(),
        CachedInputsOperation::Erase,
    )]));

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.tx_index_cache = TxIndexCache::new_for_test(BTreeMap::from([(
            outpoint2.clone(),
            CachedInputsOperation::Erase,
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn tokens_del_hierarchy() {
    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_1 = H256::random();
    let tx_id_1 = Transaction::new(1, vec![], vec![], 1).unwrap().get_id();
    let token_id_2 = H256::random();
    let tx_id_2 = Transaction::new(2, vec![], vec![], 2).unwrap().get_id();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_del_token_aux_data()
        .with(eq(token_id_1))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_token_aux_data()
        .with(eq(token_id_2))
        .times(1)
        .return_const(Ok(()));
    store.expect_del_token_id().with(eq(tx_id_1)).times(1).return_const(Ok(()));
    store.expect_del_token_id().with(eq(tx_id_2)).times(1).return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.token_issuance_cache = TokenIssuanceCache::new_for_test(
        BTreeMap::from([(token_id_1, CachedAuxDataOp::Erase)]),
        BTreeMap::from([(tx_id_1, CachedTokenIndexOp::Erase)]),
    );

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(token_id_2, CachedAuxDataOp::Erase)]),
            BTreeMap::from([(tx_id_2, CachedTokenIndexOp::Erase)]),
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}
