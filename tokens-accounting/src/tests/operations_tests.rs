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
        tokens::{
            IsTokenFreezable, IsTokenFrozen, IsTokenUnfreezable, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        Destination,
    },
    primitives::Amount,
};
use randomness::Rng;
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};

use crate::{
    FlushableTokensAccountingView, FungibleTokenData, InMemoryTokensAccounting, TokenData,
    TokensAccountingCache, TokensAccountingDB, TokensAccountingOperations, TokensAccountingView,
};

fn make_token_data(rng: &mut impl Rng, supply: TokenTotalSupply, locked: bool) -> TokenData {
    TokenData::FungibleToken(FungibleTokenData::new_unchecked(
        random_ascii_alphanumeric_string(rng, 1..5).as_bytes().to_vec(),
        rng.gen_range(1..18),
        random_ascii_alphanumeric_string(rng, 1..1024).as_bytes().to_vec(),
        supply,
        locked,
        IsTokenFrozen::No(IsTokenFreezable::No),
        Destination::AnyoneCanSpend,
    ))
}

fn make_token_issuance(
    rng: &mut impl Rng,
    supply: TokenTotalSupply,
    freezable: IsTokenFreezable,
) -> TokenIssuance {
    TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: random_ascii_alphanumeric_string(rng, 1..5).as_bytes().to_vec(),
        number_of_decimals: rng.gen_range(1..18),
        metadata_uri: random_ascii_alphanumeric_string(rng, 1..1024).as_bytes().to_vec(),
        total_supply: supply,
        is_freezable: freezable,
        authority: Destination::AnyoneCanSpend,
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_token_fungible_data_conversion(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);

    let token_data: FungibleTokenData = token_issuance.into();
    assert!(!token_data.is_locked());
    assert!(!token_data.is_frozen());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_token_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = TokenId::random_using(&mut rng);

    let mut storage = InMemoryTokensAccounting::new();
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);
    let _ = cache.issue_token(token_id, token_data.clone()).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Amount::ZERO
    );

    let consumed_data = cache.consume();
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
fn issue_token_and_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::new();
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);
    let undo = cache.issue_token(token_id, token_data.clone()).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Amount::ZERO
    );

    cache.undo(undo).unwrap();

    assert_eq!(cache.get_token_data(&token_id).unwrap(), None);
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Amount::ZERO
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_issue_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

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
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(1..1000));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);

    let _ = cache.mint_tokens(token_id, amount_to_mint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        amount_to_mint
    );

    let consumed_data = cache.consume();
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
    let token_id = TokenId::random_using(&mut rng);
    let max_amount_to_mint = Amount::from_atoms(i128::MAX as u128);
    let overflow_amount_to_mint = Amount::from_atoms(i128::MAX as u128 + 1);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

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
        max_amount_to_mint
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mint_token_multiple_times_and_over_supply(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let total_supply = Amount::from_atoms(rng.gen_range(100..100_000));
    let token_data = make_token_data(&mut rng, TokenTotalSupply::Fixed(total_supply), false);
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

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
        total_supply
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
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(1..1000));

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let undo = cache.mint_tokens(token_id, amount_to_mint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        amount_to_mint
    );

    cache.undo(undo).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        Amount::ZERO
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_token_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_data = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);

    let _ = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        (amount_to_mint - amount_to_unmint).unwrap()
    );

    let consumed_data = cache.consume();
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
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let undo = cache.unmint_tokens(token_id, amount_to_unmint).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        (amount_to_mint - amount_to_unmint).unwrap()
    );

    cache.undo(undo).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id).unwrap(),
        amount_to_mint
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unmint_token_multiple_times_and_over_minted(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let total_supply = Amount::from_atoms(rng.gen_range(100..100_000));
    let token_data = make_token_data(&mut rng, TokenTotalSupply::Fixed(total_supply), false);
    let token_id = TokenId::random_using(&mut rng);
    let amount_minted = total_supply;

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_minted)]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

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
        Amount::ZERO
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
    let token_id_1 = TokenId::random_using(&mut rng);
    let token_id_2 = TokenId::random_using(&mut rng);
    let token_id_3 = TokenId::random_using(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([
            (token_id_1, token_data_1.clone()),
            (token_id_2, token_data_2.clone()),
            (token_id_3, token_data_3.clone()),
        ]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);

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
            let locked = data.try_lock().unwrap();
            assert!(locked.is_locked());
            TokenData::FungibleToken(locked)
        }
    };

    assert_eq!(
        cache.get_token_data(&token_id_3).unwrap(),
        Some(locked_token_data_3.clone())
    );
    assert_eq!(
        cache.get_circulating_supply(&token_id_3).unwrap(),
        Amount::ZERO
    );

    let consumed_data = cache.consume();
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
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

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
    let token_id = TokenId::random_using(&mut rng);
    let amount_to_mint = Amount::from_atoms(rng.gen_range(2..1000));
    let amount_to_unmint = Amount::from_atoms(rng.gen_range(1..amount_to_mint.into_atoms()));

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, amount_to_mint)]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let undo = cache.lock_circulating_supply(token_id).unwrap();

    let locked_token_data = match token_data.clone() {
        TokenData::FungibleToken(data) => TokenData::FungibleToken(data.try_lock().unwrap()),
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
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    assert_eq!(
        cache.lock_circulating_supply(token_id),
        Err(crate::Error::SupplyIsAlreadyLocked(token_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_freeze_not_freezable_token(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::new();
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let _ = cache.issue_token(token_id, token_data).unwrap();

    assert_eq!(
        cache.freeze_token(token_id, IsTokenUnfreezable::No),
        Err(crate::Error::CannotFreezeNotFreezableToken(token_id))
    );

    assert_eq!(
        cache.unfreeze_token(token_id),
        Err(crate::Error::CannotUnfreezeTokenThatIsNotFrozen(token_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn freeze_token_and_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, Amount::from_atoms(1000))]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let undo_freeze = cache.freeze_token(token_id, IsTokenUnfreezable::No).unwrap();

    let frozen_token_data = match token_data.clone() {
        TokenData::FungibleToken(data) => {
            TokenData::FungibleToken(data.try_freeze(IsTokenUnfreezable::No).unwrap())
        }
    };

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(frozen_token_data.clone())
    );

    assert_eq!(
        cache.freeze_token(token_id, IsTokenUnfreezable::Yes),
        Err(crate::Error::TokenIsAlreadyFrozen(token_id))
    );

    assert_eq!(
        cache.mint_tokens(token_id, Amount::from_atoms(1)),
        Err(crate::Error::CannotMintFrozenToken(token_id))
    );

    assert_eq!(
        cache.unmint_tokens(token_id, Amount::from_atoms(1)),
        Err(crate::Error::CannotUnmintFrozenToken(token_id))
    );

    assert_eq!(
        cache.lock_circulating_supply(token_id),
        Err(crate::Error::CannotLockFrozenToken(token_id))
    );

    assert_eq!(
        cache.unfreeze_token(token_id),
        Err(crate::Error::CannotUnfreezeNotUnfreezableToken(token_id))
    );

    cache.undo(undo_freeze).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );

    let _ = cache.mint_tokens(token_id, Amount::from_atoms(1)).unwrap();
    let _ = cache.unmint_tokens(token_id, Amount::from_atoms(1)).unwrap();
    let _ = cache.lock_circulating_supply(token_id).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn unfreeze_token_and_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, Amount::from_atoms(1000))]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    let _ = cache.freeze_token(token_id, IsTokenUnfreezable::Yes).unwrap();
    let undo_unfreeze = cache.unfreeze_token(token_id).unwrap();

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(token_data.clone())
    );

    cache.undo(undo_unfreeze).unwrap();

    let frozen_token_data = match token_data.clone() {
        TokenData::FungibleToken(data) => {
            TokenData::FungibleToken(data.try_freeze(IsTokenUnfreezable::Yes).unwrap())
        }
    };

    assert_eq!(
        cache.get_token_data(&token_id).unwrap(),
        Some(frozen_token_data.clone())
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn freeze_unfreeze_freeze(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::from_iter([(token_id, Amount::from_atoms(1000))]),
    );
    let db = TokensAccountingDB::new(&storage);
    let mut cache = TokensAccountingCache::new(&db);

    // Freeze the token
    let _ = cache.freeze_token(token_id, IsTokenUnfreezable::Yes).unwrap();

    let TokenData::FungibleToken(token_data) = cache.get_token_data(&token_id).unwrap().unwrap();
    assert!(token_data.is_frozen());
    assert!(!token_data.can_be_frozen());
    assert!(token_data.can_be_unfrozen());

    // Unfreeze the token
    let _ = cache.unfreeze_token(token_id).unwrap();

    let TokenData::FungibleToken(token_data) = cache.get_token_data(&token_id).unwrap().unwrap();
    assert!(!token_data.is_frozen());
    assert!(token_data.can_be_frozen());
    assert!(!token_data.can_be_unfrozen());

    // All operations are now allowed
    let _ = cache.mint_tokens(token_id, Amount::from_atoms(1)).unwrap();
    let _ = cache.unmint_tokens(token_id, Amount::from_atoms(1)).unwrap();
    let _ = cache.lock_circulating_supply(token_id).unwrap();

    // Freeze again, now without an option to unfreeze
    let _ = cache.freeze_token(token_id, IsTokenUnfreezable::No).unwrap();

    let TokenData::FungibleToken(token_data) = cache.get_token_data(&token_id).unwrap().unwrap();
    assert!(token_data.is_frozen());
    assert!(!token_data.can_be_frozen());
    assert!(!token_data.can_be_unfrozen());

    assert_eq!(
        cache.unfreeze_token(token_id),
        Err(crate::Error::CannotUnfreezeNotUnfreezableToken(token_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_authority_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_id = TokenId::random_using(&mut rng);
    let token_data_1 = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let (_, some_pk) =
        crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);
    let new_authority = Destination::PublicKey(some_pk);
    let TokenData::FungibleToken(token_data_2) = token_data_1.clone();
    let token_data_2 =
        TokenData::FungibleToken(token_data_2.change_authority(new_authority.clone()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_1.clone())]),
        BTreeMap::new(),
    );
    let original_storage = storage.clone();

    // Change authority
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);
    let undo = cache.change_authority(token_id, new_authority).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_2.clone())]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);

    // undo
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);
    cache.undo(undo).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    assert_eq!(storage, original_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_authority_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_id = TokenId::random_using(&mut rng);
    let token_data_1 = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);

    let (_, some_pk) =
        crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);
    let new_authority_1 = Destination::PublicKey(some_pk);

    let (_, some_pk) =
        crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);
    let new_authority_2 = Destination::PublicKey(some_pk);
    let TokenData::FungibleToken(token_data_3) = token_data_1.clone();
    let token_data_3 =
        TokenData::FungibleToken(token_data_3.change_authority(new_authority_2.clone()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_1.clone())]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);

    // Change authority
    let mut cache = TokensAccountingCache::new(&mut db);
    let _ = cache.change_authority(token_id, new_authority_1).unwrap();
    let _ = cache.change_authority(token_id, new_authority_2).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_3.clone())]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_change_authority_for_frozen_token(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);

    // Freeze the token
    let _ = cache.freeze_token(token_id, IsTokenUnfreezable::Yes).unwrap();

    let (_, some_pk) =
        crypto::key::PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);
    let new_authority = Destination::PublicKey(some_pk);
    let TokenData::FungibleToken(token_data) = token_data.clone();
    let new_token_data =
        TokenData::FungibleToken(token_data.change_authority(new_authority.clone()));

    // Try change authority while token is frozen
    let res = cache.change_authority(token_id, new_authority.clone());

    assert_eq!(
        res.unwrap_err(),
        crate::Error::CannotChangeAuthorityForFrozenToken(token_id)
    );

    // Unfreeze token
    let _ = cache.unfreeze_token(token_id).unwrap();

    // Change authority again
    let _ = cache.change_authority(token_id, new_authority).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, new_token_data)]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_metadata_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_id = TokenId::random_using(&mut rng);
    let token_data_1 = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);
    let new_metadata = random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();
    let TokenData::FungibleToken(token_data_2) = token_data_1.clone();
    let token_data_2 =
        TokenData::FungibleToken(token_data_2.change_metadata_uri(new_metadata.clone()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_1.clone())]),
        BTreeMap::new(),
    );
    let original_storage = storage.clone();

    // Change metadata
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);
    let undo = cache.change_metadata_uri(token_id, new_metadata).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_2.clone())]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);

    // undo
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);
    cache.undo(undo).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    assert_eq!(storage, original_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn change_metadata_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_id = TokenId::random_using(&mut rng);
    let token_data_1 = make_token_data(&mut rng, TokenTotalSupply::Unlimited, false);

    let new_metadata_1 = random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();

    let new_metadata_2 = random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();
    let TokenData::FungibleToken(token_data_3) = token_data_1.clone();
    let token_data_3 =
        TokenData::FungibleToken(token_data_3.change_metadata_uri(new_metadata_2.clone()));

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_1.clone())]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);

    // Change metadata
    let mut cache = TokensAccountingCache::new(&mut db);
    let _ = cache.change_metadata_uri(token_id, new_metadata_1).unwrap();
    let _ = cache.change_metadata_uri(token_id, new_metadata_2).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data_3.clone())]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_change_metadata_for_frozen_token(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let token_issuance =
        make_token_issuance(&mut rng, TokenTotalSupply::Lockable, IsTokenFreezable::Yes);
    let token_data = TokenData::FungibleToken(token_issuance.into());
    let token_id = TokenId::random_using(&mut rng);

    let mut storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data.clone())]),
        BTreeMap::new(),
    );
    let mut db = TokensAccountingDB::new(&mut storage);
    let mut cache = TokensAccountingCache::new(&mut db);

    // Freeze the token
    let _ = cache.freeze_token(token_id, IsTokenUnfreezable::Yes).unwrap();

    let new_metadata = random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec();
    let TokenData::FungibleToken(token_data) = token_data.clone();
    let new_token_data =
        TokenData::FungibleToken(token_data.change_metadata_uri(new_metadata.clone()));

    // Try change authority while token is frozen
    let res = cache.change_metadata_uri(token_id, new_metadata.clone());

    assert_eq!(
        res.unwrap_err(),
        crate::Error::CannotChangeMetadataUriForFrozenToken(token_id)
    );

    // Unfreeze token
    let _ = cache.unfreeze_token(token_id).unwrap();

    // Change metadata again
    let _ = cache.change_metadata_uri(token_id, new_metadata).unwrap();

    let consumed_data = cache.consume();
    db.batch_write_tokens_data(consumed_data).unwrap();

    let expected_storage = InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, new_token_data)]),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}
