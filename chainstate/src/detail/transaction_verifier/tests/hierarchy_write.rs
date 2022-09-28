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

use super::flush::flush_to_storage;
use super::*;
use common::chain::{
    config::Builder as ConfigBuilder, tokens::TokenAuxiliaryData, TxMainChainIndex,
    TxMainChainPosition,
};
use mockall::predicate::eq;

#[test]
fn hierarchy_test_utxo() {
    let chain_config = ConfigBuilder::test_chain().build();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store.expect_set_undo_data().times(2).return_const(Ok(()));

    let (outpoint1, utxo1) = create_utxo(1000);
    let block_undo_id_1: Id<Block> = Id::new(H256::random());
    let (_, utxo1_undo) = create_utxo(100);
    let block_undo_1 = BlockUndo::new(None, vec![TxUndo::new(vec![utxo1_undo])]);

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_cache.add_utxo(&outpoint1, utxo1.clone(), false).unwrap();
    verifier1.utxo_block_undo.insert(
        block_undo_id_1,
        BlockUndoEntry {
            undo: block_undo_1.clone(),
            is_fresh: true,
        },
    );

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

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn hierarchy_test_tx_index() {
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
    flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[test]
fn hierarchy_test_tokens() {
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
        BTreeMap::from([(
            token_id_1,
            CachedTokensOperation::Write(token_data_1.clone()),
        )]),
        BTreeMap::from([(token_data_1.issuance_tx().get_id(), token_id_1)]),
    );

    let verifier2 = {
        let mut verifier = TransactionVerifier::new(&verifier1, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(
                token_id_2,
                CachedTokensOperation::Write(token_data_2.clone()),
            )]),
            BTreeMap::from([(token_data_2.issuance_tx().get_id(), token_id_2)]),
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush_to_storage(&mut store, consumed_verifier1).unwrap();
}
