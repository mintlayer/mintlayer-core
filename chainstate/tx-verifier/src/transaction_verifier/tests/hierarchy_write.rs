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

use crate::transaction_verifier::{
    storage::TransactionVerifierStorageError,
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
};

use super::*;
use common::chain::{
    config::Builder as ConfigBuilder, tokens::TokenAuxiliaryData, TxMainChainIndex,
    TxMainChainPosition,
};
use mockall::predicate::eq;
use pos_accounting::{AccountingBlockUndo, AccountingTxUndo, DeltaMergeUndo};
use rstest::rstest;
use test_utils::random::Seed;
use utxo::{UtxosBlockRewardUndo, UtxosBlockUndo, UtxosTxUndoWithSources};

// TODO: ConsumedUtxoCache is not checked in these tests, think how to expose it from utxo crate

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// utxo2 & block_undo2    utxo1 & block_undo1
//
// Check that data from TransactionVerifiers are flushed from one TransactionVerifier to another
// and then to the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn utxo_set_from_chain_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let block_1_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();
    let block_1_undo = UtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_1_id,
            UtxosTxUndoWithSources::new(vec![create_utxo(&mut rng, 100).1], vec![]),
        )]),
    )
    .unwrap();

    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);
    let block_2_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_2_id: Id<Transaction> = H256::from_low_u64_be(2).into();
    let block_2_undo = UtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_2_id,
            UtxosTxUndoWithSources::new(vec![create_utxo(&mut rng, 100).1], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_1_id)),
            eq(block_1_undo.clone()),
        )
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_2_id)),
            eq(block_2_undo.clone()),
        )
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.utxo_cache.add_utxo(&outpoint1, utxo1, false).unwrap();
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_1_id),
        UtxosBlockUndoEntry {
            undo: block_1_undo,
            is_fresh: true,
        },
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.add_utxo(&outpoint2, utxo2, false).unwrap();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_2_id),
            UtxosBlockUndoEntry {
                undo: block_2_undo,
                is_fresh: true,
            },
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// tx_index2              tx_index1
//
// Check that data from TransactionVerifiers are flushed from one TransactionVerifier to another
// and then to the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_index_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));
    let pos1 = TxMainChainPosition::new(H256::from_low_u64_be(1).into(), 1).into();
    let tx_index_1 = TxMainChainIndex::new(pos1, 1).unwrap();

    let outpoint2 = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));
    let pos2 = TxMainChainPosition::new(H256::from_low_u64_be(2).into(), 1).into();
    let tx_index_2 = TxMainChainIndex::new(pos2, 2).unwrap();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
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

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
        outpoint1,
        CachedInputsOperation::Write(tx_index_1),
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
            outpoint2,
            CachedInputsOperation::Write(tx_index_2),
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// token2 & tx_id2        token1 & tx_id1
//
// Check that data from TransactionVerifiers are flushed from one TransactionVerifier to another
// and then to the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_1 = H256::random_using(&mut rng);
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![], 1).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let token_id_2 = H256::random_using(&mut rng);
    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![], 2).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
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

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.token_issuance_cache = TokenIssuanceCache::new_for_test(
        BTreeMap::from([(token_id_1, CachedAuxDataOp::Write(token_data_1.clone()))]),
        BTreeMap::from([(
            token_data_1.issuance_tx().get_id(),
            CachedTokenIndexOp::Write(token_id_1),
        )]),
    );

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
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

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
//                                               utxo1 & block_undo1; utxo2 & block_undo2
//
// Spend utxo2 in TransactionVerifier2 and utxo1 in TransactionVerifier1.
// Flush and check that the data was deleted from the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn utxo_del_from_chain_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let block_1_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_1_undo: UtxosBlockUndo = Default::default();

    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);
    let block_2_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_2_undo: UtxosBlockUndo = Default::default();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_get_utxo()
        .with(eq(outpoint1.clone()))
        .times(1)
        .return_const(Ok(Some(utxo1)));
    store
        .expect_get_utxo()
        .with(eq(outpoint2.clone()))
        .times(1)
        .return_const(Ok(Some(utxo2)));

    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_1_id)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_2_id)))
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.utxo_cache.spend_utxo(&outpoint1).unwrap();
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_1_id),
        UtxosBlockUndoEntry {
            undo: block_1_undo,
            is_fresh: false,
        },
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.spend_utxo(&outpoint2).unwrap();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_2_id),
            UtxosBlockUndoEntry {
                undo: block_2_undo,
                is_fresh: false,
            },
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
//                                               tx_index1; tx_index2
//
// Erase tx_index2 in TransactionVerifier2 and tx_index1 in TransactionVerifier1.
// Flush and check that the data was deleted from the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_index_del_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));
    let outpoint2 = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
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

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
        outpoint1,
        CachedInputsOperation::Erase,
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
            outpoint2,
            CachedInputsOperation::Erase,
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
//                                               token2 & tx_id2; token1 & tx_id1
//
// Erase token2 & tx_id2 in TransactionVerifier2 and token2 & tx_id2 in TransactionVerifier1.
// Flush and check that the data was deleted from the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_del_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_1 = H256::random_using(&mut rng);
    let tx_id_1 = Transaction::new(1, vec![], vec![], 1).unwrap().get_id();
    let token_id_2 = H256::random_using(&mut rng);
    let tx_id_2 = Transaction::new(2, vec![], vec![], 2).unwrap().get_id();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
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

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.token_issuance_cache = TokenIssuanceCache::new_for_test(
        BTreeMap::from([(token_id_1, CachedAuxDataOp::Erase)]),
        BTreeMap::from([(tx_id_1, CachedTokenIndexOp::Erase)]),
    );

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
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

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// utxo1                  utxo1
//
// The data in TransactionVerifiers conflicts
// Check that data is flushed from one TransactionVerifier to another with an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn utxo_conflict_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.utxo_cache.add_utxo(&outpoint1, utxo1, false).unwrap();

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.add_utxo(&outpoint1, utxo2, false).unwrap();
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    assert_eq!(
        flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap_err(),
        TransactionVerifierStorageError::UtxoError(utxo::Error::FreshUtxoAlreadyExists)
    );

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// block                  utxo1
//
// The data in TransactionVerifiers conflicts
// Check that data from one TransactionVerifier to another was merged during flush
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn block_undo_from_chain_conflict_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let (_, utxo3) = create_utxo(&mut rng, 3000);
    let (_, utxo4) = create_utxo(&mut rng, 4000);
    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();
    let block_undo_1 = UtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo1.clone()])),
        BTreeMap::from([(
            tx_1_id,
            UtxosTxUndoWithSources::new(vec![utxo2.clone()], vec![]),
        )]),
    )
    .unwrap();
    let tx_2_id: Id<Transaction> = H256::from_low_u64_be(2).into();
    let block_undo_2 = UtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo3.clone()])),
        BTreeMap::from([(
            tx_2_id,
            UtxosTxUndoWithSources::new(vec![utxo4.clone()], vec![]),
        )]),
    )
    .unwrap();
    let expected_block_undo = UtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo1, utxo3])),
        BTreeMap::from([
            (tx_1_id, UtxosTxUndoWithSources::new(vec![utxo2], vec![])),
            (tx_2_id, UtxosTxUndoWithSources::new(vec![utxo4], vec![])),
        ]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id)),
            eq(expected_block_undo),
        )
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        UtxosBlockUndoEntry {
            undo: block_undo_1,
            is_fresh: true,
        },
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_id),
            UtxosBlockUndoEntry {
                undo: block_undo_2,
                is_fresh: true,
            },
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// tx_index2              tx_index1
//
// The data in TransactionVerifiers conflicts
// Check that tx_index1 was overwritten by tx_index2
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_index_conflict_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let outpoint1 = OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng)));
    let pos1 = TxMainChainPosition::new(H256::from_low_u64_be(1).into(), 1).into();
    let tx_index_1 = TxMainChainIndex::new(pos1, 1).unwrap();

    let pos2 = TxMainChainPosition::new(H256::from_low_u64_be(2).into(), 1).into();
    let tx_index_2 = TxMainChainIndex::new(pos2, 2).unwrap();

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_set_mainchain_tx_index()
        .with(eq(outpoint1.clone()), eq(tx_index_2.clone()))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
        outpoint1.clone(),
        CachedInputsOperation::Write(tx_index_1),
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.tx_index_cache = OptionalTxIndexCache::new_for_test(BTreeMap::from([(
            outpoint1,
            CachedInputsOperation::Write(tx_index_2),
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// token1                 token1
//
// The data in TransactionVerifiers conflicts
// Check that data is flushed from one TransactionVerifier to another with an error
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_conflict_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_1 = H256::random_using(&mut rng);
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![], 1).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![], 2).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_set_token_aux_data()
        .with(eq(token_id_1), eq(token_data_1.clone()))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_token_id()
        .with(eq(token_data_1.issuance_tx().get_id()), eq(token_id_1))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    verifier1.token_issuance_cache = TokenIssuanceCache::new_for_test(
        BTreeMap::from([(token_id_1, CachedAuxDataOp::Write(token_data_1.clone()))]),
        BTreeMap::from([(
            token_data_1.issuance_tx().get_id(),
            CachedTokenIndexOp::Write(token_id_1),
        )]),
    );

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(token_id_1, CachedAuxDataOp::Write(token_data_2.clone()))]),
            BTreeMap::from([(
                token_data_2.issuance_tx().get_id(),
                CachedTokenIndexOp::Write(token_id_1),
            )]),
        );
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    assert_eq!(
        flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap_err(),
        TransactionVerifierStorageError::TokensError(
            TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(token_id_1),
        )
    );

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_accounting_stake_pool_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, _) = create_utxo(&mut rng, 1000);
    let (outpoint2, _) = create_utxo(&mut rng, 2000);

    let (_, pub_key1) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (_, pub_key2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let pool_id_1 = pos_accounting::make_pool_id(&outpoint1);
    let pool_id_2 = pos_accounting::make_pool_id(&outpoint2);

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store
        .expect_get_pool_balance()
        .with(eq(pool_id_1))
        .times(1)
        .return_const(Ok(None));
    store
        .expect_get_pool_balance()
        .with(eq(pool_id_2))
        .times(1)
        .return_const(Ok(None));

    store.expect_get_pool_data().with(eq(pool_id_1)).times(1).return_const(Ok(None));
    store.expect_get_pool_data().with(eq(pool_id_2)).times(1).return_const(Ok(None));

    let mut verifier1 =
        TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
    let _ = verifier1
        .accounting_delta
        .create_pool(&outpoint1, pool_balance1, pub_key1)
        .unwrap();

    let mut verifier2 = verifier1.derive_child();
    let _ = verifier2
        .accounting_delta
        .create_pool(&outpoint2, pool_balance2, pub_key2)
        .unwrap();

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_accounting_stake_pool_undo_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, _) = create_utxo(&mut rng, 1000);
    let (outpoint2, _) = create_utxo(&mut rng, 2000);

    let (_, pub_key1) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (_, pub_key2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_pool_balance().return_const(Ok(None));
    store.expect_get_pool_data().return_const(Ok(None));

    store
        .expect_set_accounting_undo_data()
        .withf(move |id, undo| *id == TransactionSource::Chain(block_undo_id_1) && !undo.is_empty())
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_accounting_undo_data()
        .withf(move |id, undo| *id == TransactionSource::Chain(block_undo_id_2) && !undo.is_empty())
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier =
            TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));
        let (_, undo) = verifier
            .accounting_delta
            .create_pool(&outpoint1, pool_balance1, pub_key1)
            .unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo =
            AccountingBlockUndo::new(BTreeMap::from([(tx_id, AccountingTxUndo::new(vec![undo]))]));

        verifier.accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                AccountingBlockUndoEntry {
                    undo: block_undo,
                    is_fresh: true,
                },
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        let (_, undo) = verifier
            .accounting_delta
            .create_pool(&outpoint2, pool_balance2, pub_key2)
            .unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo =
            AccountingBlockUndo::new(BTreeMap::from([(tx_id, AccountingTxUndo::new(vec![undo]))]));

        verifier.accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                AccountingBlockUndoEntry {
                    undo: block_undo,
                    is_fresh: true,
                },
            )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_accounting_stake_pool_undo_del_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store
        .expect_get_best_block_for_utxos()
        .return_const(Ok(Some(H256::zero().into())));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_pool_balance().return_const(Ok(None));
    store.expect_get_pool_data().return_const(Ok(None));

    store
        .expect_del_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_1)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_2)))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier =
            TransactionVerifier::new(&store, &chain_config, TransactionVerifierConfig::new(true));

        verifier.accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                AccountingBlockUndoEntry {
                    undo: Default::default(),
                    is_fresh: false,
                },
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();

        verifier.accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                AccountingBlockUndoEntry {
                    undo: Default::default(),
                    is_fresh: false,
                },
            )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}
