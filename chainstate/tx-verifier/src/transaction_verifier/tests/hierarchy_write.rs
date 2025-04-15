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
use accounting::TxUndo;
use common::chain::{
    config::Builder as ConfigBuilder,
    tokens::{IsTokenFreezable, IsTokenFrozen, TokenAuxiliaryData, TokenId, TokenTotalSupply},
    DelegationId, PoolId,
};
use mockall::predicate::eq;
use orders_accounting::OrdersAccountingDeltaUndoData;
use pos_accounting::DeltaMergeUndo;
use rstest::rstest;
use test_utils::random::Seed;
use tokens_accounting::{FungibleTokenData, TokensAccountingDeltaUndoData};
use utxo::{UtxosBlockRewardUndo, UtxosTxUndoWithSources};

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
    let block_1_undo = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_1_id,
            UtxosTxUndoWithSources::new(vec![Some(create_utxo(&mut rng, 100).1)], vec![]),
        )]),
    )
    .unwrap();

    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);
    let block_2_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_2_id: Id<Transaction> = H256::from_low_u64_be(2).into();
    let block_2_undo = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_2_id,
            UtxosTxUndoWithSources::new(vec![Some(create_utxo(&mut rng, 100).1)], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
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

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_cache.add_utxo(&outpoint1, utxo1, false).unwrap();
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_1_id),
        CachedUtxoBlockUndoOp::Write(block_1_undo),
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.add_utxo(&outpoint2, utxo2, false).unwrap();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_2_id),
            CachedUtxoBlockUndoOp::Write(block_2_undo),
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

    let token_id_1 = TokenId::random_using(&mut rng);
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![]).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let token_id_2 = TokenId::random_using(&mut rng);
    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![]).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
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

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
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

    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);
    let block_2_id: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
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
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_cache.spend_utxo(&outpoint1).unwrap();
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_1_id),
        CachedUtxoBlockUndoOp::Erase,
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.spend_utxo(&outpoint2).unwrap();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_2_id),
            CachedUtxoBlockUndoOp::Erase,
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

    let token_id_1 = TokenId::random_using(&mut rng);
    let tx_id_1 = Transaction::new(1, vec![], vec![]).unwrap().get_id();
    let token_id_2 = TokenId::random_using(&mut rng);
    let tx_id_2 = Transaction::new(2, vec![], vec![]).unwrap().get_id();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
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

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
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
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
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
    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();
    let block_undo_1 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_1_id,
            UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
        )]),
    )
    .unwrap();
    let tx_2_id: Id<Transaction> = H256::from_low_u64_be(2).into();
    let block_undo_2 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_2_id,
            UtxosTxUndoWithSources::new(vec![Some(utxo2.clone())], vec![]),
        )]),
    )
    .unwrap();
    let expected_block_undo = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([
            (
                tx_1_id,
                UtxosTxUndoWithSources::new(vec![Some(utxo1)], vec![]),
            ),
            (
                tx_2_id,
                UtxosTxUndoWithSources::new(vec![Some(utxo2)], vec![]),
            ),
        ]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
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
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Write(block_undo_1),
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_id),
            CachedUtxoBlockUndoOp::Write(block_undo_2),
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
fn block_undo_from_chain_conflict_reward_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_1 = CachedUtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo1.clone()])),
        Default::default(),
    )
    .unwrap();
    let block_undo_2 = CachedUtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo2.clone()])),
        Default::default(),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Write(block_undo_1),
    )]));

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            TransactionSource::Chain(block_id),
            CachedUtxoBlockUndoOp::Write(block_undo_2),
        )]));
        verifier
    };

    let consumed_verifier2 = verifier2.consume().unwrap();
    let result = flush::flush_to_storage(&mut verifier1, consumed_verifier2);

    assert_eq!(
        result.unwrap_err(),
        TransactionVerifierStorageError::UtxoBlockUndoError(
            utxo::UtxosBlockUndoError::UndoAlreadyExistsForReward
        )
    );
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

    let token_id_1 = TokenId::random_using(&mut rng);
    let token_data_1 = TokenAuxiliaryData::new(
        Transaction::new(1, vec![], vec![]).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let token_data_2 = TokenAuxiliaryData::new(
        Transaction::new(2, vec![], vec![]).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
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

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
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

    let destination1 = new_pub_key_destination(&mut rng);
    let destination2 = new_pub_key_destination(&mut rng);

    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let pool_data1 = create_pool_data(&mut rng, destination1.clone(), destination1, pool_balance1);
    let pool_data2 = create_pool_data(&mut rng, destination2.clone(), destination2, pool_balance2);

    let pool_id_1 = PoolId::from_utxo(&outpoint1);
    let pool_id_2 = PoolId::from_utxo(&outpoint2);

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
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

    store.expect_apply_accounting_delta().times(1).return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    let _ = verifier1
        .pos_accounting_adapter
        .operations(TransactionSource::Mempool)
        .create_pool(pool_id_1, pool_data1.into())
        .unwrap();

    let mut verifier2 = verifier1.derive_child();
    let _ = verifier2
        .pos_accounting_adapter
        .operations(TransactionSource::Mempool)
        .create_pool(pool_id_2, pool_data2.into())
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

    let destination1 = new_pub_key_destination(&mut rng);
    let destination2 = new_pub_key_destination(&mut rng);

    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let pool_data1 = create_pool_data(&mut rng, destination1.clone(), destination1, pool_balance1);
    let pool_data2 = create_pool_data(&mut rng, destination2.clone(), destination2, pool_balance2);

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_pool_balance().return_const(Ok(None));
    store.expect_get_pool_data().return_const(Ok(None));
    store.expect_get_delegation_data().return_const(Ok(None));

    store
        .expect_set_pos_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_1) && undo.tx_undos().len() == 1
        })
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_pos_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_2) && undo.tx_undos().len() == 1
        })
        .times(1)
        .return_const(Ok(()));

    store.expect_apply_accounting_delta().times(1).return_const(Ok(()));

    let mut verifier1 = {
        let pool_id = PoolId::from_utxo(&outpoint1);
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id, pool_data1.into())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .pos_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id,
                TxUndo::<PoSAccountingUndo>::new(vec![undo]),
            )
            .unwrap();
        verifier
    };

    let verifier2 = {
        let pool_id = PoolId::from_utxo(&outpoint2);
        let mut verifier = verifier1.derive_child();
        let undo_pool = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id, pool_data2.into())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .pos_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_2),
                tx_id,
                TxUndo::<PoSAccountingUndo>::new(vec![undo_pool]),
            )
            .unwrap();
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
fn pos_accounting_stake_pool_and_delegation_undo_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, _) = create_utxo(&mut rng, 1000);
    let (outpoint2, _) = create_utxo(&mut rng, 2000);

    let destination1 = new_pub_key_destination(&mut rng);
    let destination2 = new_pub_key_destination(&mut rng);

    let pool_id_1 = PoolId::from_utxo(&outpoint1);
    let pool_id_2 = PoolId::from_utxo(&outpoint2);

    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let pool_data1 = create_pool_data(&mut rng, destination1.clone(), destination1, pool_balance1);
    let pool_data2 = create_pool_data(&mut rng, destination2.clone(), destination2, pool_balance2);

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_pool_balance().return_const(Ok(None));
    store.expect_get_pool_data().return_const(Ok(None));
    store.expect_get_delegation_data().return_const(Ok(None));

    store
        .expect_set_pos_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_1) && undo.tx_undos().len() == 2
        })
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_pos_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_2) && undo.tx_undos().len() == 1
        })
        .times(1)
        .return_const(Ok(()));

    store.expect_apply_accounting_delta().times(1).return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id_1, pool_data1.into())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .pos_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id,
                TxUndo::<PoSAccountingUndo>::new(vec![undo]),
            )
            .unwrap();
        verifier
    };

    let mut verifier2 = {
        let mut verifier = verifier1.derive_child();
        let undo_pool = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id_2, pool_data2.into())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .pos_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_2),
                tx_id,
                TxUndo::<PoSAccountingUndo>::new(vec![undo_pool]),
            )
            .unwrap();
        verifier
    };

    let verifier3 = {
        let mut verifier = verifier2.derive_child();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let delegation_id = DelegationId::random_using(&mut rng);

        let undo_delegation = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_delegation_id(pool_id_1, delegation_id, Destination::AnyoneCanSpend)
            .unwrap();

        verifier
            .pos_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id,
                TxUndo::<PoSAccountingUndo>::new(vec![undo_delegation]),
            )
            .unwrap();
        verifier
    };

    let consumed_verifier3 = verifier3.consume().unwrap();
    flush::flush_to_storage(&mut verifier2, consumed_verifier3).unwrap();

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
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_pool_balance().return_const(Ok(None));
    store.expect_get_pool_data().return_const(Ok(None));

    store
        .expect_del_pos_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_1)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_pos_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_2)))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);

        verifier.pos_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                CachedBlockUndoOp::Erase,
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();

        verifier.pos_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                CachedBlockUndoOp::Erase,
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
// nonce2                 nonce1
//
// Check that data from TransactionVerifiers are flushed from one TransactionVerifier to another
// and then to the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nonce_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let nonce1 = AccountNonce::new(rng.gen());
    let account1 = AccountType::Delegation(DelegationId::new(H256::random_using(&mut rng)));

    let nonce2 = AccountNonce::new(rng.gen());
    let account2 = AccountType::Delegation(DelegationId::new(H256::random_using(&mut rng)));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_set_account_nonce_count()
        .with(eq(account1), eq(nonce1))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_account_nonce_count()
        .with(eq(account2), eq(nonce2))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.account_nonce = BTreeMap::from([(account1, CachedOperation::Write(nonce1))]);

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.account_nonce = BTreeMap::from([(account2, CachedOperation::Write(nonce2))]);
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
//                                               nonce0; nonce1
//
// Erase nonce0 in TransactionVerifier2 and nonce1 in TransactionVerifier1.
// Flush and check that the data was deleted from the store
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nonce_del_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let account0 = AccountType::Delegation(DelegationId::new(H256::random_using(&mut rng)));
    let account1 = AccountType::Delegation(DelegationId::new(H256::random_using(&mut rng)));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_del_account_nonce_count()
        .with(eq(account0))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_account_nonce_count()
        .with(eq(account1))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.account_nonce = BTreeMap::from([(account1, CachedOperation::Erase)]);

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.account_nonce = BTreeMap::from([(account0, CachedOperation::Erase)]);
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
fn tokens_v1_set_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let tx_id_1: Id<Transaction> = Id::new(H256::random_using(&mut rng));
    let tx_id_2: Id<Transaction> = Id::new(H256::random_using(&mut rng));

    let input1 = TxInput::Utxo(create_utxo(&mut rng, 100).0);
    let input2 = TxInput::Utxo(create_utxo(&mut rng, 1000).0);

    let supply1 = Amount::from_atoms(100);
    let supply2 = Amount::from_atoms(200);

    let token_data1 =
        tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
            "tkn1".into(),
            0,
            Vec::new(),
            TokenTotalSupply::Unlimited,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
            Destination::AnyoneCanSpend,
        ));
    let token_data2 =
        tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
            "tkn2".into(),
            0,
            Vec::new(),
            TokenTotalSupply::Unlimited,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
            Destination::AnyoneCanSpend,
        ));

    let token_id_1 = make_token_id(&chain_config, BlockHeight::zero(), &[input1]).unwrap();
    let token_id_2 = make_token_id(&chain_config, BlockHeight::zero(), &[input2]).unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_circulating_supply().return_const(Ok(None));
    store.expect_get_token_data().return_const(Ok(None));

    store
        .expect_set_tokens_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_1)
                && undo.tx_undos().len() == 1
                && undo.tx_undos()[&tx_id_1].get().unwrap().inner().len() == 2
        })
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_tokens_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_2)
                && undo.tx_undos().len() == 1
                && undo.tx_undos()[&tx_id_2].get().unwrap().inner().len() == 2
        })
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_1, token_data1.clone())
            .unwrap();
        let undo_mint = verifier.tokens_accounting_cache.mint_tokens(token_id_1, supply1).unwrap();

        verifier
            .tokens_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id_1,
                accounting::TxUndo::new(vec![undo_issue, undo_mint]),
            )
            .unwrap();
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_2, token_data2.clone())
            .unwrap();
        let undo_mint = verifier.tokens_accounting_cache.mint_tokens(token_id_2, supply2).unwrap();

        verifier
            .tokens_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_2),
                tx_id_2,
                accounting::TxUndo::new(vec![undo_issue, undo_mint]),
            )
            .unwrap();
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
fn tokens_v1_set_issue_and_lock_undo_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let input1 = TxInput::Utxo(create_utxo(&mut rng, 100).0);
    let input2 = TxInput::Utxo(create_utxo(&mut rng, 1000).0);

    let token_data1 =
        tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
            "tkn1".into(),
            0,
            Vec::new(),
            TokenTotalSupply::Lockable,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
            Destination::AnyoneCanSpend,
        ));
    let token_data2 =
        tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
            "tkn2".into(),
            0,
            Vec::new(),
            TokenTotalSupply::Lockable,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
            Destination::AnyoneCanSpend,
        ));

    let token_id_1 = make_token_id(&chain_config, BlockHeight::zero(), &[input1]).unwrap();
    let token_id_2 = make_token_id(&chain_config, BlockHeight::zero(), &[input2]).unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_circulating_supply().return_const(Ok(None));
    store.expect_get_token_data().return_const(Ok(None));

    store
        .expect_set_tokens_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_1) && undo.tx_undos().len() == 2
        })
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_tokens_accounting_undo_data()
        .withf(move |id, undo| {
            *id == TransactionSource::Chain(block_undo_id_2) && undo.tx_undos().len() == 1
        })
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_1, token_data1.clone())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .tokens_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id,
                accounting::TxUndo::new(vec![undo_issue]),
            )
            .unwrap();
        verifier
    };

    let mut verifier2 = {
        let mut verifier = verifier1.derive_child();
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_2, token_data2.clone())
            .unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .tokens_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_2),
                tx_id,
                accounting::TxUndo::new(vec![undo_issue]),
            )
            .unwrap();
        verifier
    };

    let verifier3 = {
        let mut verifier = verifier2.derive_child();
        let undo_lock =
            verifier.tokens_accounting_cache.lock_circulating_supply(token_id_1).unwrap();
        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        verifier
            .tokens_accounting_block_undo
            .add_tx_undo(
                TransactionSource::Chain(block_undo_id_1),
                tx_id,
                accounting::TxUndo::new(vec![undo_lock]),
            )
            .unwrap();
        verifier
    };

    let consumed_verifier3 = verifier3.consume().unwrap();
    flush::flush_to_storage(&mut verifier2, consumed_verifier3).unwrap();

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut verifier1, consumed_verifier2).unwrap();

    let consumed_verifier1 = verifier1.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier1).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_v1_del_undo_hierarchy(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    store.expect_get_circulating_supply().return_const(Ok(None));
    store.expect_get_token_data().return_const(Ok(None));

    store
        .expect_del_tokens_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_1)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_tokens_accounting_undo_data()
        .with(eq(TransactionSource::Chain(block_undo_id_2)))
        .times(1)
        .return_const(Ok(()));

    let mut verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);

        verifier.tokens_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                CachedBlockUndoOp::Erase,
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();

        verifier.tokens_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                CachedBlockUndoOp::Erase,
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
fn utxo_set_from_chain_hierarchy_with_derived(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();
    let tx_1_undo = UtxosTxUndoWithSources::new(vec![Some(create_utxo(&mut rng, 100).1)], vec![]);

    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);
    let tx_2_id: Id<Transaction> = H256::from_low_u64_be(2).into();
    let tx_2_undo = UtxosTxUndoWithSources::new(vec![Some(create_utxo(&mut rng, 100).1)], vec![]);

    let reward_undo = UtxosBlockRewardUndo::new(vec![create_utxo(&mut rng, 100).1]);

    let expected_block_undo = CachedUtxosBlockUndo::new(
        Some(reward_undo.clone()),
        BTreeMap::from([(tx_1_id, tx_1_undo.clone()), (tx_2_id, tx_2_undo.clone())]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id)),
            eq(expected_block_undo),
        )
        .times(1)
        .return_const(Ok(()));

    let mut verifier_base = TransactionVerifier::new(&store, &chain_config);

    let mut verifier_tx_1 = verifier_base.derive_child();
    verifier_tx_1.utxo_cache.add_utxo(&outpoint1, utxo1, false).unwrap();
    verifier_tx_1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Write(
            CachedUtxosBlockUndo::new(None, BTreeMap::from([(tx_1_id, tx_1_undo)])).unwrap(),
        ),
    )]));
    let consumed_verifier = verifier_tx_1.consume().unwrap();
    flush::flush_to_storage(&mut verifier_base, consumed_verifier).unwrap();

    let mut verifier_tx_2 = verifier_base.derive_child();
    verifier_tx_2.utxo_cache.add_utxo(&outpoint2, utxo2, false).unwrap();
    verifier_tx_2.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Write(
            CachedUtxosBlockUndo::new(None, BTreeMap::from([(tx_2_id, tx_2_undo)])).unwrap(),
        ),
    )]));
    let consumed_verifier = verifier_tx_2.consume().unwrap();
    flush::flush_to_storage(&mut verifier_base, consumed_verifier).unwrap();

    let mut verifier_reward = verifier_base.derive_child();
    verifier_reward.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Write(
            CachedUtxosBlockUndo::new(Some(reward_undo), BTreeMap::new()).unwrap(),
        ),
    )]));
    let consumed_verifier = verifier_reward.consume().unwrap();
    flush::flush_to_storage(&mut verifier_base, consumed_verifier).unwrap();

    let consumed_verifier = verifier_base.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn utxo_del_from_chain_hierarchy_with_derived(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));

    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_orders_data()
        .times(1)
        .return_const(Ok(OrdersAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));
    store.expect_del_utxo_undo_data().times(1).return_const(Ok(()));

    let mut verifier_base = TransactionVerifier::new(&store, &chain_config);

    let mut verifier_tx_1 = verifier_base.derive_child();
    verifier_tx_1.utxo_cache.add_utxo(&outpoint1, utxo1, false).unwrap();
    verifier_tx_1.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Erase,
    )]));
    let consumed_verifier = verifier_tx_1.consume().unwrap();
    flush::flush_to_storage(&mut verifier_base, consumed_verifier).unwrap();

    let mut verifier_tx_2 = verifier_base.derive_child();
    verifier_tx_2.utxo_cache.add_utxo(&outpoint2, utxo2, false).unwrap();
    verifier_tx_2.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
        TransactionSource::Chain(block_id),
        CachedUtxoBlockUndoOp::Erase,
    )]));
    let consumed_verifier = verifier_tx_2.consume().unwrap();
    flush::flush_to_storage(&mut verifier_base, consumed_verifier).unwrap();

    let consumed_verifier = verifier_base.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_verifier).unwrap();
}
