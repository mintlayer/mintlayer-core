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
    accounting_undo_cache::CachedBlockUndo,
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
};

use super::*;
use chainstate_types::GenBlockIndex;
use common::{
    chain::{
        config::Builder as ConfigBuilder,
        tokens::{IsTokenFreezable, IsTokenFrozen, TokenAuxiliaryData, TokenId, TokenTotalSupply},
        DelegationId, PoolId,
    },
    primitives::H256,
};
use mockall::predicate::eq;
use pos_accounting::PoSAccountingStorageRead;
use rstest::rstest;
use test_utils::random::Seed;
use tokens_accounting::{FungibleTokenData, TokensAccountingStorageRead};
use utxo::{UtxosStorageRead, UtxosTxUndoWithSources};

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// utxo2                  utxo1                  utxo0
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_utxo(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let (outpoint0, utxo0) = create_utxo(&mut rng, 100);
    let (outpoint1, utxo1) = create_utxo(&mut rng, 1000);
    let (outpoint2, utxo2) = create_utxo(&mut rng, 2000);

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_utxo()
        .with(eq(outpoint0.clone()))
        .times(2)
        .return_const(Ok(Some(utxo0.clone())));
    store
        .expect_get_utxo()
        .with(eq(outpoint2.clone()))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.utxo_cache.add_utxo(&outpoint1, utxo1.clone(), false).unwrap();
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_cache.add_utxo(&outpoint2, utxo2.clone(), false).unwrap();
        verifier
    };

    assert_eq!(
        verifier1.get_utxo(&outpoint0).unwrap().as_ref(),
        Some(&utxo0)
    );
    assert_eq!(
        verifier1.get_utxo(&outpoint1).unwrap().as_ref(),
        Some(&utxo1)
    );
    assert_eq!(verifier1.get_utxo(&outpoint2).unwrap(), None);
    assert_eq!(
        verifier2.get_utxo(&outpoint0).unwrap().as_ref(),
        Some(&utxo0)
    );
    assert_eq!(
        verifier2.get_utxo(&outpoint1).unwrap().as_ref(),
        Some(&utxo1)
    );
    assert_eq!(
        verifier2.get_utxo(&outpoint2).unwrap().as_ref(),
        Some(&utxo2)
    );
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// block_undo2            block_undo1            block_undo0
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_undo_from_chain(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let block_undo_id_0: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_0 = TransactionSource::Chain(block_undo_id_0);
    let (_, utxo0_undo) = create_utxo(&mut rng, 100);
    let block_undo_0 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            H256::random_using(&mut rng).into(),
            UtxosTxUndoWithSources::new(vec![Some(utxo0_undo)], vec![]),
        )]),
    )
    .unwrap();

    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_1 = TransactionSource::Chain(block_undo_id_1);
    let (_, utxo1_undo) = create_utxo(&mut rng, 100);
    let block_undo_1 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            H256::random_using(&mut rng).into(),
            UtxosTxUndoWithSources::new(vec![Some(utxo1_undo)], vec![]),
        )]),
    )
    .unwrap();

    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_2 = TransactionSource::Chain(block_undo_id_2);
    let (_, utxo2_undo) = create_utxo(&mut rng, 100);
    let block_undo_2 = CachedUtxosBlockUndo::new(
        None,
        BTreeMap::from([(
            H256::random_using(&mut rng).into(),
            UtxosTxUndoWithSources::new(vec![Some(utxo2_undo)], vec![]),
        )]),
    )
    .unwrap();

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_undo_data()
        .with(eq(block_undo_source_0))
        .times(2)
        .return_const(Ok(Some(block_undo_0.clone())));
    store
        .expect_get_undo_data()
        .with(eq(block_undo_source_2))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            block_undo_source_1,
            CachedUtxoBlockUndoOp::Write(block_undo_1.clone()),
        )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.utxo_block_undo = UtxosBlockUndoCache::new_for_test(BTreeMap::from([(
            block_undo_source_2,
            CachedUtxoBlockUndoOp::Write(block_undo_2.clone()),
        )]));
        verifier
    };

    assert_eq!(
        verifier1.get_undo_data(block_undo_source_0).unwrap().as_ref(),
        Some(&block_undo_0)
    );
    assert_eq!(
        verifier1.get_undo_data(block_undo_source_1).unwrap().as_ref(),
        Some(&block_undo_1)
    );
    assert_eq!(verifier1.get_undo_data(block_undo_source_2).unwrap(), None);
    assert_eq!(
        verifier2.get_undo_data(block_undo_source_0).unwrap().as_ref(),
        Some(&block_undo_0)
    );
    assert_eq!(
        verifier2.get_undo_data(block_undo_source_1).unwrap().as_ref(),
        Some(&block_undo_1)
    );
    assert_eq!(
        verifier2.get_undo_data(block_undo_source_2).unwrap().as_ref(),
        Some(&block_undo_2)
    );
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// token2 & tx_id2        token1 & tx_id1        token0 & tx_id0
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_tokens_v0(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let token_id_0 = TokenId::random_using(&mut rng);
    let token_data_0 = TokenAuxiliaryData::new(
        Transaction::new(0, vec![], vec![]).unwrap(),
        Id::new(H256::random_using(&mut rng)),
    );

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
    store
        .expect_get_token_aux_data()
        .with(eq(token_id_0))
        .times(2)
        .return_const(Ok(Some(token_data_0.clone())));
    store
        .expect_get_token_id_from_issuance_tx()
        .with(eq(token_data_0.issuance_tx().get_id()))
        .times(2)
        .return_const(Ok(Some(token_id_0)));
    store
        .expect_get_token_aux_data()
        .with(eq(token_id_2))
        .times(1)
        .return_const(Ok(None));
    store
        .expect_get_token_id_from_issuance_tx()
        .with(eq(token_data_2.issuance_tx().get_id()))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(token_id_1, CachedAuxDataOp::Write(token_data_1.clone()))]),
            BTreeMap::from([(
                token_data_1.issuance_tx().get_id(),
                CachedTokenIndexOp::Write(token_id_1),
            )]),
        );
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.token_issuance_cache = TokenIssuanceCache::new_for_test(
            BTreeMap::from([(token_id_2, CachedAuxDataOp::Read(token_data_2.clone()))]),
            BTreeMap::from([(
                token_data_2.issuance_tx().get_id(),
                CachedTokenIndexOp::Read(token_id_2),
            )]),
        );
        verifier
    };

    assert_eq!(
        verifier1.get_token_aux_data(&token_id_0).unwrap().as_ref(),
        Some(&token_data_0)
    );
    assert_eq!(
        verifier1.get_token_aux_data(&token_id_1).unwrap().as_ref(),
        Some(&token_data_1)
    );
    assert_eq!(verifier1.get_token_aux_data(&token_id_2).unwrap(), None);
    assert_eq!(
        verifier2.get_token_aux_data(&token_id_0).unwrap().as_ref(),
        Some(&token_data_0)
    );
    assert_eq!(
        verifier2.get_token_aux_data(&token_id_1).unwrap().as_ref(),
        Some(&token_data_1)
    );
    assert_eq!(
        verifier2.get_token_aux_data(&token_id_2).unwrap().as_ref(),
        Some(&token_data_2)
    );

    assert_eq!(
        verifier1
            .get_token_id_from_issuance_tx(token_data_0.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_0)
    );
    assert_eq!(
        verifier1
            .get_token_id_from_issuance_tx(token_data_1.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_1)
    );
    assert_eq!(
        verifier1
            .get_token_id_from_issuance_tx(token_data_2.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        None
    );
    assert_eq!(
        verifier2
            .get_token_id_from_issuance_tx(token_data_0.issuance_tx().get_id())
            .unwrap()
            .as_ref(),
        Some(&token_id_0)
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
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_block_index(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_index = GenBlockIndex::genesis(&chain_config);
    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_gen_block_index()
        .with(eq(Id::<GenBlock>::from(block_id)))
        .times(2)
        .return_const(Ok(Some(block_index)));

    let verifier1 = TransactionVerifier::new(&store, &chain_config);
    verifier1.get_gen_block_index(&block_id.into()).unwrap();

    let verifier2 = verifier1.derive_child();
    verifier2.get_gen_block_index(&block_id.into()).unwrap();
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// pool2/undo             pool1/undo             pool0/undo
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_stake_pool(#[case] seed: Seed) {
    use accounting::TxUndo;

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let destination0 = new_pub_key_destination(&mut rng);
    let destination1 = new_pub_key_destination(&mut rng);
    let destination2 = new_pub_key_destination(&mut rng);

    let pool_balance0 = Amount::from_atoms(100);
    let pool_balance1 = Amount::from_atoms(200);
    let pool_balance2 = Amount::from_atoms(300);

    let pool_data0 = create_pool_data(&mut rng, destination0.clone(), destination0, pool_balance0);
    let pool_data1 = create_pool_data(&mut rng, destination1.clone(), destination1, pool_balance1);
    let pool_data2 = create_pool_data(&mut rng, destination2.clone(), destination2, pool_balance2);

    let pool_id_0 = PoolId::random_using(&mut rng);
    let pool_id_1 = PoolId::random_using(&mut rng);
    let pool_id_2 = PoolId::random_using(&mut rng);

    let block_undo_id_0: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_0 = TransactionSource::Chain(block_undo_id_0);
    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_1 = TransactionSource::Chain(block_undo_id_1);
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_2 = TransactionSource::Chain(block_undo_id_2);

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_pool_balance()
        .with(eq(pool_id_0))
        .times(2)
        .return_const(Ok(Some(pool_balance0)));
    store
        .expect_get_pool_balance()
        .with(eq(pool_id_1))
        .times(3)
        .return_const(Ok(None));
    store
        .expect_get_pool_balance()
        .with(eq(pool_id_2))
        .times(3)
        .return_const(Ok(None));

    store
        .expect_get_pool_data()
        .with(eq(pool_id_0))
        .times(2)
        .return_const(Ok(Some(pool_data0.clone().into())));
    store.expect_get_pool_data().with(eq(pool_id_1)).times(1).return_const(Ok(None));
    store.expect_get_pool_data().with(eq(pool_id_2)).times(2).return_const(Ok(None));

    store
        .expect_get_pos_accounting_undo()
        .with(eq(block_undo_source_0))
        .times(2)
        .return_const(Ok(None));
    store
        .expect_get_pos_accounting_undo()
        .with(eq(block_undo_source_2))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id_1, pool_data1.clone().into())
            .unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo = CachedBlockUndo::new(
            None,
            BTreeMap::from([(tx_id, TxUndo::<PoSAccountingUndo>::new(vec![undo]))]),
        )
        .unwrap();

        verifier.pos_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                CachedBlockUndoOp::Write(block_undo),
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        let undo = verifier
            .pos_accounting_adapter
            .operations(TransactionSource::Mempool)
            .create_pool(pool_id_2, pool_data2.clone().into())
            .unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo = CachedBlockUndo::<PoSAccountingUndo>::new(
            None,
            BTreeMap::from([(tx_id, TxUndo::<PoSAccountingUndo>::new(vec![undo]))]),
        )
        .unwrap();

        verifier.pos_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                CachedBlockUndoOp::Write(block_undo),
            )]));
        verifier
    };

    // fetch pool balances
    assert_eq!(
        verifier1.get_pool_balance(pool_id_0).unwrap(),
        Some(pool_balance0)
    );
    assert_eq!(
        verifier1.get_pool_balance(pool_id_1).unwrap(),
        Some(pool_balance1)
    );
    assert_eq!(
        verifier1.get_pool_balance(pool_id_2).unwrap(),
        Some(Amount::ZERO)
    );

    assert_eq!(
        verifier2.get_pool_balance(pool_id_0).unwrap(),
        Some(pool_balance0)
    );
    assert_eq!(
        verifier2.get_pool_balance(pool_id_1).unwrap(),
        Some(pool_balance1)
    );
    assert_eq!(
        verifier2.get_pool_balance(pool_id_2).unwrap(),
        Some(pool_balance2)
    );

    // fetch pool data
    assert_eq!(
        verifier1.get_pool_data(pool_id_0).unwrap(),
        Some(pool_data0.clone().into())
    );
    assert_eq!(
        verifier1.get_pool_data(pool_id_1).unwrap(),
        Some(pool_data1.clone().into())
    );
    assert_eq!(verifier1.get_pool_data(pool_id_2).unwrap(), None);

    assert_eq!(
        verifier2.get_pool_data(pool_id_0).unwrap(),
        Some(pool_data0.into())
    );
    assert_eq!(
        verifier2.get_pool_data(pool_id_1).unwrap(),
        Some(pool_data1.into())
    );
    assert_eq!(
        verifier2.get_pool_data(pool_id_2).unwrap(),
        Some(pool_data2.into())
    );

    // fetch undo
    assert!(verifier1.get_pos_accounting_undo(block_undo_source_0).unwrap().is_none());
    assert!(verifier1.get_pos_accounting_undo(block_undo_source_1).unwrap().is_some());
    assert!(verifier1.get_pos_accounting_undo(block_undo_source_2).unwrap().is_none());
    assert!(verifier2.get_pos_accounting_undo(block_undo_source_0).unwrap().is_none());
    assert!(verifier2.get_pos_accounting_undo(block_undo_source_1).unwrap().is_some());
    assert!(verifier2.get_pos_accounting_undo(block_undo_source_2).unwrap().is_some());
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// nonce2                 nonce1                 nonce0
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_nonce(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain().build();

    let nonce0 = AccountNonce::new(rng.gen());
    let account0 = AccountType::Delegation(DelegationId::random_using(&mut rng));

    let nonce1 = AccountNonce::new(rng.gen());
    let account1 = AccountType::Delegation(DelegationId::random_using(&mut rng));

    let nonce2 = AccountNonce::new(rng.gen());
    let account2 = AccountType::Delegation(DelegationId::random_using(&mut rng));

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_account_nonce_count()
        .with(eq(account0))
        .times(2)
        .return_const(Ok(Some(nonce0)));
    store
        .expect_get_account_nonce_count()
        .with(eq(account2))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        verifier.account_nonce = BTreeMap::from([(account1, CachedOperation::Read(nonce1))]);
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        verifier.account_nonce = BTreeMap::from([(account2, CachedOperation::Read(nonce2))]);
        verifier
    };

    assert_eq!(
        verifier1.get_account_nonce_count(account0).unwrap(),
        Some(nonce0)
    );
    assert_eq!(
        verifier1.get_account_nonce_count(account1).unwrap(),
        Some(nonce1)
    );
    assert_eq!(verifier1.get_account_nonce_count(account2).unwrap(), None);

    assert_eq!(
        verifier2.get_account_nonce_count(account0).unwrap(),
        Some(nonce0)
    );
    assert_eq!(
        verifier2.get_account_nonce_count(account1).unwrap(),
        Some(nonce1)
    );
    assert_eq!(
        verifier2.get_account_nonce_count(account2).unwrap(),
        Some(nonce2)
    );
}

// Create the following hierarchy:
//
// TransactionVerifier -> TransactionVerifier -> MockStore
// token2/supply2/undo    token1/supply1/undo    token0/supply0/undo
//
// Check that data can be accessed through derived entities
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn hierarchy_test_tokens_v1(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = ConfigBuilder::test_chain().build();

    let supply0 = Amount::from_atoms(100);
    let supply1 = Amount::from_atoms(200);
    let supply2 = Amount::from_atoms(300);

    let token_data0 =
        tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
            "tkn0".into(),
            0,
            Vec::new(),
            TokenTotalSupply::Unlimited,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
            Destination::AnyoneCanSpend,
        ));
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

    let token_id_0 = TokenId::random_using(&mut rng);
    let token_id_1 = TokenId::random_using(&mut rng);
    let token_id_2 = TokenId::random_using(&mut rng);

    let block_undo_id_0: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_0 = TransactionSource::Chain(block_undo_id_0);
    let block_undo_id_1: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_1 = TransactionSource::Chain(block_undo_id_1);
    let block_undo_id_2: Id<Block> = Id::new(H256::random_using(&mut rng));
    let block_undo_source_2 = TransactionSource::Chain(block_undo_id_2);

    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    store
        .expect_get_circulating_supply()
        .with(eq(token_id_0))
        .times(2)
        .return_const(Ok(Some(supply0)));
    store
        .expect_get_circulating_supply()
        .with(eq(token_id_1))
        .times(3)
        .return_const(Ok(None));
    store
        .expect_get_circulating_supply()
        .with(eq(token_id_2))
        .times(3)
        .return_const(Ok(None));

    store
        .expect_get_token_data()
        .with(eq(token_id_0))
        .times(2)
        .return_const(Ok(Some(token_data0.clone())));
    store
        .expect_get_token_data()
        .with(eq(token_id_1))
        .times(1)
        .return_const(Ok(None));
    store
        .expect_get_token_data()
        .with(eq(token_id_2))
        .times(2)
        .return_const(Ok(None));

    store
        .expect_get_tokens_accounting_undo()
        .with(eq(block_undo_source_0))
        .times(2)
        .return_const(Ok(None));
    store
        .expect_get_tokens_accounting_undo()
        .with(eq(block_undo_source_2))
        .times(1)
        .return_const(Ok(None));

    let verifier1 = {
        let mut verifier = TransactionVerifier::new(&store, &chain_config);
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_1, token_data1.clone())
            .unwrap();
        let undo_mint = verifier.tokens_accounting_cache.mint_tokens(token_id_1, supply1).unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo = CachedBlockUndo::new(
            None,
            BTreeMap::from([(tx_id, accounting::TxUndo::new(vec![undo_issue, undo_mint]))]),
        )
        .unwrap();

        verifier.tokens_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_1),
                CachedBlockUndoOp::Write(block_undo),
            )]));
        verifier
    };

    let verifier2 = {
        let mut verifier = verifier1.derive_child();
        let undo_issue = verifier
            .tokens_accounting_cache
            .issue_token(token_id_2, token_data2.clone())
            .unwrap();
        let undo_mint = verifier.tokens_accounting_cache.mint_tokens(token_id_2, supply2).unwrap();

        let tx_id: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let block_undo = CachedBlockUndo::new(
            None,
            BTreeMap::from([(tx_id, accounting::TxUndo::new(vec![undo_issue, undo_mint]))]),
        )
        .unwrap();

        verifier.tokens_accounting_block_undo =
            AccountingBlockUndoCache::new_for_test(BTreeMap::from([(
                TransactionSource::Chain(block_undo_id_2),
                CachedBlockUndoOp::Write(block_undo),
            )]));
        verifier
    };

    // fetch pool balances
    assert_eq!(
        verifier1.get_circulating_supply(&token_id_0).unwrap(),
        Some(supply0)
    );
    assert_eq!(
        verifier1.get_circulating_supply(&token_id_1).unwrap(),
        Some(supply1)
    );
    assert_eq!(
        verifier1.get_circulating_supply(&token_id_2).unwrap(),
        Some(Amount::ZERO)
    );

    assert_eq!(
        verifier2.get_circulating_supply(&token_id_0).unwrap(),
        Some(supply0)
    );
    assert_eq!(
        verifier2.get_circulating_supply(&token_id_1).unwrap(),
        Some(supply1)
    );
    assert_eq!(
        verifier2.get_circulating_supply(&token_id_2).unwrap(),
        Some(supply2)
    );

    // fetch pool data
    assert_eq!(
        verifier1.get_token_data(&token_id_0).unwrap(),
        Some(token_data0.clone())
    );
    assert_eq!(
        verifier1.get_token_data(&token_id_1).unwrap(),
        Some(token_data1.clone())
    );
    assert_eq!(verifier1.get_token_data(&token_id_2).unwrap(), None);

    assert_eq!(
        verifier2.get_token_data(&token_id_0).unwrap(),
        Some(token_data0.clone())
    );
    assert_eq!(
        verifier2.get_token_data(&token_id_1).unwrap(),
        Some(token_data1.clone())
    );
    assert_eq!(
        verifier2.get_token_data(&token_id_2).unwrap(),
        Some(token_data2.clone())
    );

    // fetch undo
    assert!(verifier1.get_tokens_accounting_undo(block_undo_source_0).unwrap().is_none());
    assert!(verifier1.get_tokens_accounting_undo(block_undo_source_1).unwrap().is_some());
    assert!(verifier1.get_tokens_accounting_undo(block_undo_source_2).unwrap().is_none());
    assert!(verifier2.get_tokens_accounting_undo(block_undo_source_0).unwrap().is_none());
    assert!(verifier2.get_tokens_accounting_undo(block_undo_source_1).unwrap().is_some());
    assert!(verifier2.get_tokens_accounting_undo(block_undo_source_2).unwrap().is_some());
}
