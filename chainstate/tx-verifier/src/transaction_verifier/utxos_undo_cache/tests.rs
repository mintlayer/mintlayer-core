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

use crate::{
    transaction_verifier::{
        flush,
        storage::TransactionVerifierStorageRef,
        tests::{create_utxo, mock},
    },
    TransactionVerifier,
};

use common::{
    chain::{config::Builder as ConfigBuilder, Block},
    primitives::H256,
};
use pos_accounting::DeltaMergeUndo;
use test_utils::random::Seed;
use tokens_accounting::TokensAccountingDeltaUndoData;
use utxo::{UtxosBlockRewardUndo, UtxosTxUndoWithSources};

use mockall::predicate::eq;
use rstest::rstest;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_txs_in_hierarchy_default(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let (_, utxo3) = create_utxo(&mut rng, 3000);
    let (_, utxo3_2) = create_utxo(&mut rng, 3100);

    let block_id_1: Id<Block> = H256::random_using(&mut rng).into();
    let block_id_2: Id<Block> = H256::random_using(&mut rng).into();

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_2: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_3: Id<Transaction> = H256::random_using(&mut rng).into();

    let expected_block_undo_1 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([
            (
                tx_id_1,
                UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
            ),
            (
                tx_id_2,
                UtxosTxUndoWithSources::new(vec![Some(utxo2.clone())], vec![tx_id_1.into()]),
            ),
        ]),
    )
    .unwrap();

    let expected_block_undo_2 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_id_3,
            UtxosTxUndoWithSources::new(vec![Some(utxo3.clone()), Some(utxo3_2.clone())], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id_1)),
            eq(expected_block_undo_1),
        )
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id_2)),
            eq(expected_block_undo_2),
        )
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_1),
            tx_id_1,
            UtxosTxUndoWithSources::new(vec![Some(utxo1)], vec![]),
        )
        .unwrap();

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_1),
            tx_id_2,
            UtxosTxUndoWithSources::new(vec![Some(utxo2)], vec![tx_id_1.into()]),
        )
        .unwrap();

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_2),
            tx_id_3,
            UtxosTxUndoWithSources::new(vec![Some(utxo3), Some(utxo3_2)], vec![]),
        )
        .unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
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
fn connect_txs_in_hierarchy_disposable(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let (_, utxo3) = create_utxo(&mut rng, 3000);
    let (_, utxo3_2) = create_utxo(&mut rng, 3100);

    let block_id_1: Id<Block> = H256::random_using(&mut rng).into();
    let block_id_2: Id<Block> = H256::random_using(&mut rng).into();

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_2: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_3: Id<Transaction> = H256::random_using(&mut rng).into();

    let expected_block_undo_1 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([
            (
                tx_id_1,
                UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
            ),
            (
                tx_id_2,
                UtxosTxUndoWithSources::new(vec![Some(utxo2.clone())], vec![tx_id_1.into()]),
            ),
        ]),
    )
    .unwrap();

    let expected_block_undo_2 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_id_3,
            UtxosTxUndoWithSources::new(vec![Some(utxo3.clone()), Some(utxo3_2.clone())], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id_1)),
            eq(expected_block_undo_1),
        )
        .times(1)
        .return_const(Ok(()));
    store
        .expect_set_utxo_undo_data()
        .with(
            eq(TransactionSource::Chain(block_id_2)),
            eq(expected_block_undo_2),
        )
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    let mut verifier2 = base_verifier.derive_child();
    verifier2
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_1),
            tx_id_1,
            UtxosTxUndoWithSources::new(vec![Some(utxo1)], vec![]),
        )
        .unwrap();

    let consumed_verifier2 = verifier2.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_verifier2).unwrap();

    let mut verifier3 = base_verifier.derive_child();
    verifier3
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_1),
            tx_id_2,
            UtxosTxUndoWithSources::new(vec![Some(utxo2)], vec![tx_id_1.into()]),
        )
        .unwrap();

    verifier3
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id_2),
            tx_id_3,
            UtxosTxUndoWithSources::new(vec![Some(utxo3), Some(utxo3_2)], vec![]),
        )
        .unwrap();

    let consumed_verifier3 = verifier3.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_verifier3).unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_txs_in_hierarchy_twice(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);

    let block_id: Id<Block> = H256::random_using(&mut rng).into();

    let tx_id: Id<Transaction> = H256::random_using(&mut rng).into();

    let expected_block_undo = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_id,
            UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
        )]),
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
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id),
            tx_id,
            UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
        )
        .unwrap();

    // it's an error to add the same undo via the same verifier
    let result = base_verifier.utxo_block_undo.add_tx_undo(
        TransactionSource::Chain(block_id),
        tx_id,
        UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
    );
    assert_eq!(
        result.unwrap_err(),
        ConnectTransactionError::UtxoBlockUndoError(utxo::UtxosBlockUndoError::UndoAlreadyExists(
            tx_id
        ))
    );

    // It's an not an error to add the same undo via derived verifier.
    // There is no way to distinguish this case with current approach because info is not fetched on add.
    let mut derived_verifier = base_verifier.derive_child();

    derived_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Chain(block_id),
            tx_id,
            UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
        )
        .unwrap();

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_reward_in_hierarchy_twice(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);

    let block_id: Id<Block> = H256::random_using(&mut rng).into();

    let expected_block_undo = CachedUtxosBlockUndo::new(
        Some(UtxosBlockRewardUndo::new(vec![utxo1.clone()])),
        BTreeMap::new(),
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
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    base_verifier
        .utxo_block_undo
        .add_reward_undo(
            TransactionSource::Chain(block_id),
            UtxosBlockRewardUndo::new(vec![utxo1.clone()]),
        )
        .unwrap();

    // it's an error to add the same undo via the same verifier
    let result = base_verifier.utxo_block_undo.add_reward_undo(
        TransactionSource::Chain(block_id),
        UtxosBlockRewardUndo::new(vec![utxo1.clone()]),
    );
    assert_eq!(
        result.unwrap_err(),
        ConnectTransactionError::UtxoBlockUndoError(
            utxo::UtxosBlockUndoError::UndoAlreadyExistsForReward
        )
    );

    // It's an not an error to add the same undo via derived verifier.
    // There is no way to distinguish this case with current approach because info is not fetched on add.
    let mut derived_verifier = base_verifier.derive_child();

    derived_verifier
        .utxo_block_undo
        .add_reward_undo(
            TransactionSource::Chain(block_id),
            UtxosBlockRewardUndo::new(vec![utxo1.clone()]),
        )
        .unwrap();

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn disconnect_txs_in_hierarchy_default(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let (_, utxo3) = create_utxo(&mut rng, 3000);
    let (_, utxo3_2) = create_utxo(&mut rng, 3100);

    let block_id_1: Id<Block> = H256::random_using(&mut rng).into();
    let block_id_2: Id<Block> = H256::random_using(&mut rng).into();

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_2: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_3: Id<Transaction> = H256::random_using(&mut rng).into();

    let block_undo_db = BTreeMap::from_iter([
        (
            TransactionSource::Chain(block_id_1),
            CachedUtxosBlockUndo::new(
                None,
                BTreeMap::from([
                    (
                        tx_id_1,
                        UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
                    ),
                    (
                        tx_id_2,
                        UtxosTxUndoWithSources::new(
                            vec![Some(utxo2.clone())],
                            vec![tx_id_1.into()],
                        ),
                    ),
                ]),
            )
            .unwrap(),
        ),
        (
            TransactionSource::Chain(block_id_2),
            CachedUtxosBlockUndo::new(
                None,
                BTreeMap::from([(
                    tx_id_3,
                    UtxosTxUndoWithSources::new(
                        vec![Some(utxo3.clone()), Some(utxo3_2.clone())],
                        vec![],
                    ),
                )]),
            )
            .unwrap(),
        ),
    ]);

    let fetch_block_undo =
        |tx_source| -> Result<Option<CachedUtxosBlockUndo>, ConnectTransactionError> {
            Ok(block_undo_db.get(&tx_source).cloned())
        };

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_id_1)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_id_2)))
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    // Try undo tx1 with a dependency
    let can_disconnect = base_verifier
        .utxo_block_undo
        .can_disconnect_transaction(
            &TransactionSource::Chain(block_id_1),
            &tx_id_1,
            fetch_block_undo,
        )
        .unwrap();
    assert!(!can_disconnect);
    let result = base_verifier.utxo_block_undo.take_tx_undo(
        &TransactionSource::Chain(block_id_1),
        &tx_id_1,
        fetch_block_undo,
    );
    assert_eq!(
        result.unwrap_err(),
        ConnectTransactionError::UtxoBlockUndoError(
            utxo::UtxosBlockUndoError::TxUndoWithDependency(tx_id_1)
        )
    );

    // Undo tx2
    let can_disconnect = base_verifier
        .utxo_block_undo
        .can_disconnect_transaction(
            &TransactionSource::Chain(block_id_1),
            &tx_id_2,
            fetch_block_undo,
        )
        .unwrap();
    assert!(can_disconnect);
    base_verifier
        .utxo_block_undo
        .take_tx_undo(
            &TransactionSource::Chain(block_id_1),
            &tx_id_2,
            fetch_block_undo,
        )
        .unwrap();

    // Undo tx1 now that it doesn't have a dependency from tx2
    let can_disconnect = base_verifier
        .utxo_block_undo
        .can_disconnect_transaction(
            &TransactionSource::Chain(block_id_1),
            &tx_id_1,
            fetch_block_undo,
        )
        .unwrap();
    assert!(can_disconnect);
    base_verifier
        .utxo_block_undo
        .take_tx_undo(
            &TransactionSource::Chain(block_id_1),
            &tx_id_1,
            fetch_block_undo,
        )
        .unwrap();

    let can_disconnect = base_verifier
        .utxo_block_undo
        .can_disconnect_transaction(
            &TransactionSource::Chain(block_id_2),
            &tx_id_3,
            fetch_block_undo,
        )
        .unwrap();
    assert!(can_disconnect);
    base_verifier
        .utxo_block_undo
        .take_tx_undo(
            &TransactionSource::Chain(block_id_2),
            &tx_id_3,
            fetch_block_undo,
        )
        .unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn disconnect_txs_in_hierarchy_disposable(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);
    let (_, utxo3) = create_utxo(&mut rng, 3000);
    let (_, utxo3_2) = create_utxo(&mut rng, 3100);

    let block_id_1: Id<Block> = H256::random_using(&mut rng).into();
    let block_id_2: Id<Block> = H256::random_using(&mut rng).into();

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_2: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_3: Id<Transaction> = H256::random_using(&mut rng).into();

    let block_undo_1 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([
            (
                tx_id_1,
                UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
            ),
            (
                tx_id_2,
                UtxosTxUndoWithSources::new(vec![Some(utxo2.clone())], vec![tx_id_1.into()]),
            ),
        ]),
    )
    .unwrap();
    let block_undo_2 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            tx_id_3,
            UtxosTxUndoWithSources::new(vec![Some(utxo3.clone()), Some(utxo3_2.clone())], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_undo_data()
        .with(eq(TransactionSource::Chain(block_id_1)))
        .return_const(Ok(Some(block_undo_1.clone())));
    store
        .expect_get_undo_data()
        .with(eq(TransactionSource::Chain(block_id_2)))
        .return_const(Ok(Some(block_undo_2.clone())));

    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_id_1)))
        .times(1)
        .return_const(Ok(()));
    store
        .expect_del_utxo_undo_data()
        .with(eq(TransactionSource::Chain(block_id_2)))
        .times(1)
        .return_const(Ok(()));
    store.expect_batch_write().times(1).return_const(Ok(()));
    store
        .expect_batch_write_tokens_data()
        .times(1)
        .return_const(Ok(TokensAccountingDeltaUndoData::new()));
    store
        .expect_batch_write_delta()
        .times(1)
        .return_const(Ok(DeltaMergeUndo::new()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    let mut derived_verifier = base_verifier.derive_child();

    {
        let fetch_block_undo = |tx_source| -> Result<
            Option<CachedUtxosBlockUndo>,
            ConnectTransactionError,
        > { Ok(base_verifier.get_undo_data(tx_source)?) };

        // Try undo tx1 with a dependency
        let can_disconnect = derived_verifier
            .utxo_block_undo
            .can_disconnect_transaction(
                &TransactionSource::Chain(block_id_1),
                &tx_id_1,
                fetch_block_undo,
            )
            .unwrap();
        assert!(!can_disconnect);
        let result = derived_verifier.utxo_block_undo.take_tx_undo(
            &TransactionSource::Chain(block_id_1),
            &tx_id_1,
            fetch_block_undo,
        );
        assert_eq!(
            result.unwrap_err(),
            ConnectTransactionError::UtxoBlockUndoError(
                utxo::UtxosBlockUndoError::TxUndoWithDependency(tx_id_1)
            )
        );

        // Undo tx2
        let can_disconnect = derived_verifier
            .utxo_block_undo
            .can_disconnect_transaction(
                &TransactionSource::Chain(block_id_1),
                &tx_id_2,
                fetch_block_undo,
            )
            .unwrap();
        assert!(can_disconnect);
        derived_verifier
            .utxo_block_undo
            .take_tx_undo(
                &TransactionSource::Chain(block_id_1),
                &tx_id_2,
                fetch_block_undo,
            )
            .unwrap();
    }

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    // Undo tx1 now that it doesn't have a dependency from tx2
    let mut derived_verifier = base_verifier.derive_child();

    {
        let fetch_block_undo = |tx_source| -> Result<
            Option<CachedUtxosBlockUndo>,
            ConnectTransactionError,
        > { Ok(base_verifier.get_undo_data(tx_source)?) };

        let can_disconnect = derived_verifier
            .utxo_block_undo
            .can_disconnect_transaction(
                &TransactionSource::Chain(block_id_1),
                &tx_id_1,
                fetch_block_undo,
            )
            .unwrap();
        assert!(can_disconnect);
        derived_verifier
            .utxo_block_undo
            .take_tx_undo(
                &TransactionSource::Chain(block_id_1),
                &tx_id_1,
                fetch_block_undo,
            )
            .unwrap();
    }

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    // Undo tx3 from another block
    let mut derived_verifier = base_verifier.derive_child();
    {
        let fetch_block_undo = |tx_source| -> Result<
            Option<CachedUtxosBlockUndo>,
            ConnectTransactionError,
        > { Ok(base_verifier.get_undo_data(tx_source)?) };

        let can_disconnect = derived_verifier
            .utxo_block_undo
            .can_disconnect_transaction(
                &TransactionSource::Chain(block_id_2),
                &tx_id_3,
                fetch_block_undo,
            )
            .unwrap();
        assert!(can_disconnect);
        derived_verifier
            .utxo_block_undo
            .take_tx_undo(
                &TransactionSource::Chain(block_id_2),
                &tx_id_3,
                fetch_block_undo,
            )
            .unwrap();
    }

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    let consumed_base_verifier = base_verifier.consume().unwrap();
    flush::flush_to_storage(&mut store, consumed_base_verifier).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_disconnect_for_mempool(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);
    let (_, utxo2) = create_utxo(&mut rng, 2000);

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();
    let tx_id_2: Id<Transaction> = H256::random_using(&mut rng).into();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Mempool,
            tx_id_1,
            UtxosTxUndoWithSources::new(vec![Some(utxo1)], vec![]),
        )
        .unwrap();

    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Mempool,
            tx_id_2,
            UtxosTxUndoWithSources::new(vec![Some(utxo2)], vec![]),
        )
        .unwrap();

    let mut derived_verifier = base_verifier.derive_child();

    {
        let fetch_block_undo = |tx_source| -> Result<
            Option<CachedUtxosBlockUndo>,
            ConnectTransactionError,
        > { Ok(base_verifier.get_undo_data(tx_source)?) };

        derived_verifier
            .utxo_block_undo
            .take_tx_undo(&TransactionSource::Mempool, &tx_id_2, fetch_block_undo)
            .unwrap();
    }

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    let fetch_block_undo =
        |_| -> Result<Option<CachedUtxosBlockUndo>, ConnectTransactionError> { Ok(None) };

    base_verifier
        .utxo_block_undo
        .take_tx_undo(&TransactionSource::Mempool, &tx_id_1, fetch_block_undo)
        .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_disconnect_connect_for_mempool(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let (_, utxo1) = create_utxo(&mut rng, 1000);

    let tx_id_1: Id<Transaction> = H256::random_using(&mut rng).into();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));

    let mut base_verifier = TransactionVerifier::new(&store, &chain_config);

    // Connect a transaction in base
    base_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Mempool,
            tx_id_1,
            UtxosTxUndoWithSources::new(vec![Some(utxo1.clone())], vec![]),
        )
        .unwrap();

    let mut derived_verifier = base_verifier.derive_child();

    // Disconnect a transaction in derived and flush
    {
        let fetch_block_undo = |tx_source| -> Result<
            Option<CachedUtxosBlockUndo>,
            ConnectTransactionError,
        > { Ok(base_verifier.get_undo_data(tx_source)?) };

        derived_verifier
            .utxo_block_undo
            .take_tx_undo(&TransactionSource::Mempool, &tx_id_1, fetch_block_undo)
            .unwrap();
    }

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();

    // Connect a transaction in derived again and flush
    let mut derived_verifier = base_verifier.derive_child();

    derived_verifier
        .utxo_block_undo
        .add_tx_undo(
            TransactionSource::Mempool,
            tx_id_1,
            UtxosTxUndoWithSources::new(vec![Some(utxo1)], vec![]),
        )
        .unwrap();

    let consumed_derived_verifier = derived_verifier.consume().unwrap();
    flush::flush_to_storage(&mut base_verifier, consumed_derived_verifier).unwrap();
}
