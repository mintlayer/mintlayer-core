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

//use crate::detail::transaction_verifier::flush::flush_to_storage;

use super::*;

use common::chain::{
    config::Builder as ConfigBuilder, tokens::TokenAuxiliaryData, OutPoint, TxMainChainIndex,
    TxMainChainPosition,
};
use mockall::predicate;
use utxo::UtxosStorageRead;

#[test]
fn hierarchy_test_utxo() {
    let chain_config = ConfigBuilder::test_chain().build();

    //let outpoint0 = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::random())), 0);
    //let block_undo_id_0: Id<Block> = Id::new(H256::random());

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    //store.expect_set_best_block_for_utxos().times(1).return_const(Ok(()));
    store
        .expect_batch_write()
        //.with(predicate::eq(outpoint0.clone()))
        .times(1)
        .return_const(Ok(()));
    //store
    //    .expect_set_utxo()
    //    //.with(predicate::eq(outpoint0.clone()))
    //    .times(2)
    //    .return_const(Ok(()));
    store
        .expect_set_undo_data()
        //.with(predicate::eq(block_undo_id_0))
        .times(2)
        .return_const(Ok(()));

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

    let consumed_verifier2 = verifier2.consume().expect("verifier can be consumer");
    flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().expect("verifier can be consumer");
    flush_to_storage(&mut store, consumed_verifier1).unwrap();
}
