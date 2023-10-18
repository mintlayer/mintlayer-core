// Copyright (c) 2023 RBB S.r.l
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

use common::{
    chain::{
        tokens::{TokenId, TokenTotalSupply},
        Destination, OutPointSourceId, TxInput, UtxoOutPoint,
    },
    primitives::{Amount, Id, H256},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    random_string,
};

use crate::{
    FlushableTokensAccountingView, FungibleTokenData, InMemoryTokensAccounting, TokenData,
    TokensAccountingCache, TokensAccountingDB, TokensAccountingOperations, TokensAccountingView,
};

fn make_token_data(rng: &mut impl Rng, supply: TokenTotalSupply, locked: bool) -> TokenData {
    TokenData::FungibleToken(FungibleTokenData::new(
        random_string(rng, 1..5).as_bytes().to_vec(),
        rng.gen_range(1..18),
        random_string(rng, 1..1024).as_bytes().to_vec(),
        supply,
        locked,
        Destination::AnyoneCanSpend,
    ))
}

fn make_token_id(rng: &mut impl Rng) -> TokenId {
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(rng))),
        0,
    );
    let input = TxInput::Utxo(outpoint);
    common::chain::tokens::make_token_id(&[input]).unwrap()
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_token_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::new();
    let mut cache = TokensAccountingCache::new(&mut storage);
    let _ = cache.issue_token(token_id, token_data.clone()).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(cache.get_circulating_supply(&token_id).unwrap(), None);

    let consumed_data = cache.consume();
    let mut db = TokensAccountingDB::new(&mut storage);
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::new(),
    );

    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_token_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::new();
    let mut cache = TokensAccountingCache::new(&mut storage);
    let undo = cache.issue_token(token_id, token_data.clone()).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(cache.get_circulating_supply(&token_id).unwrap(), None);

    cache.undo(undo).unwrap();

    assert_eq!(cache.get_token_data(&token_id).unwrap(), None);
    assert_eq!(cache.get_circulating_supply(&token_id).unwrap(), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_issue_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    assert_eq!(
        cache.issue_token(token_id, token_data),
        Err(crate::Error::TokenAlreadyExists(token_id))
    );

    let new_token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    assert_eq!(
        cache.issue_token(token_id, new_token_data),
        Err(crate::Error::TokenAlreadyExists(token_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_token_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(1..1000));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    let _ = cache.mint_tokens(token_id, amount_to_mint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(amount_to_mint)
    );

    let consumed_data = cache.consume();
    let mut db = TokensAccountingDB::new(&mut storage);
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );

    assert_eq!(storage, expected_storage);
}

// Technically TokenTotalSupply::Unlimited is limited by i128::MAX due to accounting arithmetics
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_token_unlimited_max(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);
    let max_amount_to_mint = Amount::from_atoms(i128::MAX as u128);
    let overflow_amount_to_mint = Amount::from_atoms(i128::MAX as u128 + 1);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let mut cache = TokensAccountingCache::new(&mut storage);

    let res_overflow = cache.mint_tokens(token_id, overflow_amount_to_mint);
    assert_eq!(
        res_overflow,
        Err(crate::Error::AccountingError(
            accounting::Error::ArithmeticErrorToSignedFailed
        ))
    );

    let _ = cache.mint_tokens(token_id, max_amount_to_mint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(max_amount_to_mint)
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_token_multiple_times_and_over_supply(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let total_supply = Amount::from_atoms(rng.gen_range(100..100_000));
    let token_data = make_token_data(&mut rng, TokenTotalSupply::Fixed(total_supply), false);
    let token_id = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let mut cache = TokensAccountingCache::new(&mut storage);

    test_utils::split_value(&mut rng, total_supply.into_atoms()).iter().for_each(
        |amount_to_mint| {
            let _ = cache.mint_tokens(token_id, Amount::from_atoms(*amount_to_mint)).unwrap();
        },
    );

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(total_supply)
    );

    // Try to mint over total supply
    let exceed_supply_by = Amount::from_atoms(rng.gen_range(1..100));
    assert_eq!(
        cache.mint_tokens(token_id, exceed_supply_by),
        Err(crate::Error::MintExceedsSupplyLimit(
            exceed_supply_by,
            total_supply,
            token_id
        ))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_token_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(1..1000));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    let undo = cache.mint_tokens(token_id, amount_to_mint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(amount_to_mint)
    );

    cache.undo(undo).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(cache.get_circulating_supply(&token_id).unwrap(), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_token_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    let _ = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        amount_to_mint - amount_to_unmint
    );

    let consumed_data = cache.consume();
    let mut db = TokensAccountingDB::new(&mut storage);
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::from_iter([(token_id, (amount_to_mint - amount_to_unmint).unwrap())]),
    );

    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_token_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    let undo = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        amount_to_mint - amount_to_unmint
    );

    cache.undo(undo).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(amount_to_mint)
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_token_multiple_times_and_over_minted(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let total_supply = Amount::from_atoms(rng.gen_range(100..100_000));
    let token_data = make_token_data(&mut rng, TokenTotalSupply::Fixed(total_supply), false);
    let token_id = make_token_id(&mut rng);
    let amount_minted = total_supply;

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_minted)]),
    );
    let mut cache = TokensAccountingCache::new(&mut storage);

    let exceed_minted_by = (amount_minted + Amount::from_atoms(1)).unwrap();
    assert_eq!(
        cache.unmint_tokens(token_id, exceed_minted_by),
        Err(crate::Error::NotEnoughCirculatingSupplyToUnmint(
            amount_minted,
            exceed_minted_by,
            token_id
        ))
    );

    test_utils::split_value(&mut rng, amount_minted.into_atoms()).iter().for_each(
        |amount_to_unmint| {
            let _ = cache.unmint_tokens(token_id, Amount::from_atoms(*amount_to_unmint)).unwrap();
        },
    );

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Some(Amount::ZERO)
    );

    // Try to unmint over circulating supply
    let exceed_minted_by = Amount::from_atoms(rng.gen_range(1..100));
    assert_eq!(
        cache.unmint_tokens(token_id, exceed_minted_by),
        Err(crate::Error::NotEnoughCirculatingSupplyToUnmint(
            Amount::ZERO,
            exceed_minted_by,
            token_id
        ))
    );
}
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_supply_only_if_lockable(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data_1 = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_data_2 = make_token_data(
        &mut rng,
        TokenTotalSupply::Fixed(Amount::from_atoms(1)),
        false,
    );
    let token_data_3 = make_token_data(&mut rng, TokenTotalSupply::Lockable, false);
    let token_id_1 = make_token_id(&mut rng);
    let token_id_2 = make_token_id(&mut rng);
    let token_id_3 = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([
            (token_id_1, token_data_1.clone()),
            (token_id_2, token_data_2.clone()),
            (token_id_3, token_data_3.clone()),
        ]),
        BTreeMap::new(),
    );
    let mut cache = TokensAccountingCache::new(&mut storage);

    let res1 = cache.lock_circulating_supply(token_id_1);
    assert_eq!(
        res1,
        Err(crate::Error::CannotLockNotLockableSupply(token_id_1))
    );

    let res2 = cache.lock_circulating_supply(token_id_2);
    assert_eq!(
        res2,
        Err(crate::Error::CannotLockNotLockableSupply(token_id_2))
    );

    let _ = cache.lock_circulating_supply(token_id_3);

    let locked_token_data_3 = match token_data_3 {
        TokenData::FungibleToken(data) => {
            assert!(!data.is_locked());
            let locked = data.lock().unwrap();
            assert!(locked.is_locked());
            TokenData::FungibleToken(locked)
        }
    };

    assert_eq!(
        cache.get_token_data(&token_id_3).unwrap(),
        Some(locked_token_data_3.clone())
    );
    assert_eq!(cache.get_circulating_supply(&token_id_3).unwrap(), None);

    let consumed_data = cache.consume();
    let mut db = TokensAccountingDB::new(&mut storage);
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([
            (token_id_1, token_data_1),
            (token_id_2, token_data_2),
            (token_id_3, locked_token_data_3),
        ]),
        BTreeMap::new(),
    );

    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_supply_and_try_mint_unmint(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Lockable, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);

    // Mint more
    let _ = cache.mint_tokens(token_id, amount_to_mint).unwrap();
    // Unmint some
    let _ = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();

    // Lock supply
    let _ = cache.lock_circulating_supply(token_id).unwrap();

    // Try to mint
    assert_eq!(
        cache.mint_tokens(token_id, amount_to_mint),
        Err(crate::Error::CannotMintFromLockedSupply(token_id))
    );
    // Try to unmint
    assert_eq!(
        cache.unmint_tokens(token_id, amount_to_unmint),
        Err(crate::Error::CannotUnmintFromLockedSupply(token_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn lock_supply_undo_mint_unmint(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Lockable, false);
    let token_id = make_token_id(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    let undo = cache.lock_circulating_supply(token_id).unwrap();

    let locked_token_data = match token_data.clone() {
        TokenData::FungibleToken(data) => TokenData::FungibleToken(data.lock().unwrap()),
    };

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(locked_token_data.clone())
    );

    cache.undo(undo).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );

    // Mint more
    let _ = cache.mint_tokens(token_id, amount_to_mint).unwrap();
    // Unmint some
    let _ = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_lock_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Lockable, true);
    let token_id = make_token_id(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );

    let mut cache = TokensAccountingCache::new(&mut storage);
    assert_eq!(
        cache.lock_circulating_supply(token_id),
        Err(crate::Error::SupplyIsAlreadyLocked(token_id))
    );
}
