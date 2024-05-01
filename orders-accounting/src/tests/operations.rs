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
    chain::{output_value::OutputValue, tokens::TokenId, Destination, OrderData, OrderId},
    primitives::Amount,
};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    cache::OrdersAccountingCache, operations::OrdersAccountingOperations,
    view::FlushableOrdersAccountingView, InMemoryOrdersAccounting, OrdersAccountingDB,
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
        BTreeMap::from_iter([(order_id, order_data.ask().amount())]),
        BTreeMap::from_iter([(order_id, order_data.give().amount())]),
    );

    assert_eq!(expected_storage, storage);
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
        Some(order_data.ask().amount()),
        cache.get_ask_balance(&order_id).unwrap()
    );
    assert_eq!(
        Some(order_data.give().amount()),
        cache.get_give_balance(&order_id).unwrap()
    );

    cache.undo(undo).unwrap();

    assert_eq!(None, cache.get_order_data(&order_id).unwrap().as_ref());
    assert_eq!(None, cache.get_ask_balance(&order_id).unwrap());
    assert_eq!(None, cache.get_give_balance(&order_id).unwrap());

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(InMemoryOrdersAccounting::new(), storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_order_must_converge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let ask = rng.gen_range(1u128..1000);
    let give = rng.gen_range(1u128..1000);
    let fill_orders = test_utils::split_value(&mut rng, ask);

    let ask = OutputValue::Coin(Amount::from_atoms(ask));
    let give = OutputValue::Coin(Amount::from_atoms(give));

    let order_id = OrderId::random_using(&mut rng);
    let order_data = OrderData::new(Destination::AnyoneCanSpend, ask.clone(), give.clone());
    let mut storage = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, ask.amount())]),
        BTreeMap::from_iter([(order_id, give.amount())]),
    );
    let mut db = OrdersAccountingDB::new(&mut storage);
    let mut cache = OrdersAccountingCache::new(&db);

    for fill in fill_orders {
        let _ = cache.fill_order(order_id, OutputValue::Coin(Amount::from_atoms(fill))).unwrap();
    }

    db.batch_write_orders_data(cache.consume()).unwrap();

    assert_eq!(InMemoryOrdersAccounting::new(), storage);
}

// FIXME: more tests
