// Copyright (c) 2024 RBB S.r.l
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
        output_value::OutputValue, tokens::TokenId, Destination, OrderData, OrderId, OrdersVersion,
    },
    primitives::Amount,
};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    cache::OrdersAccountingCache, operations::OrdersAccountingOperations,
    view::FlushableOrdersAccountingView, Error, InMemoryOrdersAccounting, OrdersAccountingDB,
    OrdersAccountingView,
};

fn make_order_data(rng: &mut impl Rng) -> OrderData {
    let token_id = TokenId::random_using(rng);
    OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(Amount::from_atoms(rng.gen_range(1u128..1000))),
        OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen_range(1u128..1000))),
    )
}

fn output_value_amount(value: &OutputValue) -> Amount {
    match value {
        OutputValue::Coin(amount) | OutputValue::TokenV1(_, amount) => *amount,
        OutputValue::TokenV0(_) => panic!("unsupported token"),
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let mut storage = InMemoryOrdersAccounting::new();
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let _ = cache.create_order(order_id, order_data.clone()).unwrap();

    db.batch_write_orders_data(cache.consume()).unwrap();

    let expected_storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );

    assert_eq!(expected_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    {
        let storage = InMemoryOrdersAccounting::new();
        let db = OrdersAccountingDB::new(&storage);
        let mut cache = OrdersAccountingCache::new(&db);

        let _ = cache.create_order(order_id, order_data.clone()).unwrap();

        assert_eq!(
            cache.create_order(order_id, order_data.clone()),
            Err(Error::OrderAlreadyExists(order_id))
        );
    }

    {
        let storage = InMemoryOrdersAccounting::from_values(
            BTreeMap::from_iter([(order_id, order_data.clone())]),
            BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
            BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
        );
        let db = OrdersAccountingDB::new(&storage);
        let mut cache = OrdersAccountingCache::new(&db);

        assert_eq!(
            cache.create_order(order_id, order_data.clone()),
            Err(Error::OrderAlreadyExists(order_id))
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_and_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let mut storage = InMemoryOrdersAccounting::new();
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let undo = cache.create_order(order_id, order_data.clone()).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        output_value_amount(order_data.ask()),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        output_value_amount(order_data.give()),
        cache.get_give_balance(&order_id).unwrap()
    );

    cache.undo(undo).unwrap();

    assert_eq!(None, cache.get_order_data(&order_id).unwrap().as_ref());
    assert_eq!(Amount::ZERO, cache.get_ask_balance(&order_id).unwrap());
    assert_eq!(Amount::ZERO, cache.get_give_balance(&order_id).unwrap());

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(InMemoryOrdersAccounting::new(), storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conclude_order_and_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    // try to conclude non-existing order
    {
        let random_order = OrderId::random_using(&mut rng);
        let result = cache.conclude_order(random_order);
        assert_eq!(
            result.unwrap_err(),
            Error::AttemptedConcludeNonexistingOrderData(random_order)
        );
    }

    let _ = cache.conclude_order(order_id).unwrap();

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(InMemoryOrdersAccounting::new(), storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conclude_order_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let db = OrdersAccountingDB::new(&storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let _ = cache.conclude_order(order_id).unwrap();

    assert_eq!(
        cache.conclude_order(order_id,),
        Err(Error::AttemptedConcludeNonexistingOrderData(order_id))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn conclude_order_and_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let original_storage = storage.clone();
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let undo = cache.conclude_order(order_id).unwrap();

    assert_eq!(None, cache.get_order_data(&order_id).unwrap().as_ref());
    assert_eq!(Amount::ZERO, cache.get_ask_balance(&order_id).unwrap());
    assert_eq!(Amount::ZERO, cache.get_give_balance(&order_id).unwrap());

    cache.undo(undo).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        output_value_amount(order_data.ask()),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        output_value_amount(order_data.give()),
        cache.get_give_balance(&order_id).unwrap()
    );

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(original_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_entire_order_and_flush(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = make_order_data(&mut rng);

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    // try to fill non-existing order
    {
        let random_order = OrderId::random_using(&mut rng);
        let result = cache.fill_order(random_order, output_value_amount(order_data.ask()), version);
        assert_eq!(result.unwrap_err(), Error::OrderDataNotFound(random_order));
    }

    // try to overbid
    {
        let ask_amount = output_value_amount(order_data.ask());
        let fill = (ask_amount + Amount::from_atoms(1)).unwrap();
        let result = cache.fill_order(order_id, fill, version);
        assert_eq!(
            result.unwrap_err(),
            Error::OrderOverbid(
                order_id,
                ask_amount,
                (ask_amount + Amount::from_atoms(1)).unwrap()
            )
        );
    }

    let _ = cache
        .fill_order(order_id, output_value_amount(order_data.ask()), version)
        .unwrap();

    db.batch_write_orders_data(cache.consume()).unwrap();

    let expected_storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data)]),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(expected_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_partially_and_flush(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let token_id = TokenId::random_using(&mut rng);
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, Amount::from_atoms(3)),
        OutputValue::Coin(Amount::from_atoms(10)),
    );

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let _ = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(2),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(7),
        cache.get_give_balance(&order_id).unwrap()
    );

    let _ = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(1),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(4),
        cache.get_give_balance(&order_id).unwrap()
    );

    let _ = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(Amount::ZERO, cache.get_ask_balance(&order_id).unwrap());
    let expected_give_balance = match version {
        OrdersVersion::V0 => Amount::ZERO,
        OrdersVersion::V1 => Amount::from_atoms(1),
    };
    assert_eq!(
        expected_give_balance,
        cache.get_give_balance(&order_id).unwrap()
    );

    db.batch_write_orders_data(cache.consume()).unwrap();

    let expected_give_balances = match version {
        OrdersVersion::V0 => BTreeMap::new(),
        OrdersVersion::V1 => BTreeMap::from_iter([(order_id, Amount::from_atoms(1))]),
    };
    let expected_storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data)]),
        BTreeMap::new(),
        expected_give_balances,
    );
    assert_eq!(expected_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_partially_and_undo(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let token_id = TokenId::random_using(&mut rng);
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, Amount::from_atoms(3)),
        OutputValue::Coin(Amount::from_atoms(10)),
    );

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let original_storage = storage.clone();
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let undo1 = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    let undo2 = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    let undo3 = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(Amount::ZERO, cache.get_ask_balance(&order_id).unwrap());
    let expected_give_balance = match version {
        OrdersVersion::V0 => Amount::ZERO,
        OrdersVersion::V1 => Amount::from_atoms(1),
    };
    assert_eq!(
        expected_give_balance,
        cache.get_give_balance(&order_id).unwrap()
    );

    cache.undo(undo3).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(1),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(4),
        cache.get_give_balance(&order_id).unwrap()
    );

    cache.undo(undo2).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(2),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(7),
        cache.get_give_balance(&order_id).unwrap()
    );

    cache.undo(undo1).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(3),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(10),
        cache.get_give_balance(&order_id).unwrap()
    );

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(original_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_partially_and_conclude(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let token_id = TokenId::random_using(&mut rng);
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, Amount::from_atoms(3)),
        OutputValue::Coin(Amount::from_atoms(10)),
    );

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let _ = cache.fill_order(order_id, Amount::from_atoms(1), version).unwrap();

    assert_eq!(
        Some(&order_data),
        cache.get_order_data(&order_id).unwrap().as_ref()
    );
    assert_eq!(
        Amount::from_atoms(2),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Amount::from_atoms(7),
        cache.get_give_balance(&order_id).unwrap()
    );

    let _ = cache.conclude_order(order_id).unwrap();

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(InMemoryOrdersAccounting::new(), storage);
}

// If total give balance of an order is split into a random number of fill operations
// they must exhaust the order entirely.
// For V0 implementation there should not be any change left.
// For V1 it is allowed for some dust to be left in the give balance.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_must_converge(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let ask_atoms = rng.gen_range(1u128..1_000_000_000);
    let give_atoms = rng.gen_range(1u128..1_000_000_000);
    let ask_amount = Amount::from_atoms(ask_atoms);
    let give_amount = Amount::from_atoms(give_atoms);
    let fill_orders = test_utils::split_value(&mut rng, ask_amount.into_atoms());

    let ask = OutputValue::Coin(ask_amount);
    let give = OutputValue::Coin(give_amount);

    let order_id = OrderId::random_using(&mut rng);
    let order_data = OrderData::new(Destination::AnyoneCanSpend, ask.clone(), give.clone());
    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, ask_amount)]),
        BTreeMap::from_iter([(order_id, give_amount)]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    // Accumulate all fractional parts to later compare with dust balance
    let mut remainder = 0f64;

    for fill in fill_orders {
        let _ = cache.fill_order(order_id, Amount::from_atoms(fill), version).unwrap();

        let integer_result = give_atoms * fill / ask_atoms;
        let float_result = (give_atoms * fill) as f64 / ask_atoms as f64;
        // Collect only positive fractional point.
        // This is required to work around the fact that 12./4. can give 2.9999999
        if float_result as u128 >= integer_result {
            remainder += float_result.fract();
        }
    }

    db.batch_write_orders_data(cache.consume()).unwrap();

    let expected_give_balance = match version {
        OrdersVersion::V0 => BTreeMap::new(),
        OrdersVersion::V1 => {
            let tolerance: f64 = 1e-7;
            if remainder < tolerance {
                BTreeMap::new()
            } else {
                BTreeMap::from_iter([(order_id, Amount::from_atoms(remainder.round() as u128))])
            }
        }
    };

    let expected_storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data)]),
        BTreeMap::new(),
        expected_give_balance,
    );
    assert_eq!(expected_storage, storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn fill_order_underbid(#[case] seed: Seed, #[case] version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let order_id = OrderId::random_using(&mut rng);
    let token_id = TokenId::random_using(&mut rng);
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(Amount::from_atoms(3)),
        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
    );

    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.ask()))]),
        BTreeMap::from_iter([(order_id, output_value_amount(order_data.give()))]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    let result = cache.fill_order(order_id, Amount::from_atoms(1), version);

    match version {
        OrdersVersion::V0 => {
            assert!(result.is_ok());
            assert_eq!(
                Some(&order_data),
                cache.get_order_data(&order_id).unwrap().as_ref()
            );
            assert_eq!(
                Amount::from_atoms(2),
                cache.get_ask_balance(&order_id).unwrap()
            );
            assert_eq!(
                Amount::from_atoms(1),
                cache.get_give_balance(&order_id).unwrap()
            );

            let _ = cache.fill_order(order_id, Amount::from_atoms(2), version).unwrap();

            assert_eq!(
                Some(&order_data),
                cache.get_order_data(&order_id).unwrap().as_ref()
            );
            assert_eq!(Amount::ZERO, cache.get_ask_balance(&order_id).unwrap());
            assert_eq!(Amount::ZERO, cache.get_give_balance(&order_id).unwrap());
        }
        OrdersVersion::V1 => {
            assert_eq!(
                result.unwrap_err(),
                Error::OrderUnderbid(order_id, Amount::from_atoms(1))
            );

            assert_eq!(
                cache.fill_order(order_id, Amount::from_atoms(2), version).unwrap_err(),
                Error::OrderUnderbid(order_id, Amount::from_atoms(2))
            );

            let _ = cache.fill_order(order_id, Amount::from_atoms(3), version).unwrap();
        }
    }

    db.batch_write_orders_data(cache.consume()).unwrap();

    let expected_storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data)]),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(expected_storage, storage);
}
