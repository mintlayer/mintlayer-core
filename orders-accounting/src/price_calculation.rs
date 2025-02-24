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

use common::{
    chain::{OrderId, OrdersVersion},
    primitives::Amount,
    Uint256,
};
use utils::ensure;

use crate::{error::Result, Error, OrdersAccountingView};

pub fn calculate_fill_order(
    view: &impl OrdersAccountingView,
    order_id: OrderId,
    fill_amount_in_ask_currency: Amount,
    orders_version: OrdersVersion,
) -> Result<Amount> {
    match orders_version {
        OrdersVersion::V0 => calculate_fill_order_based_on_remaining_balances(
            view,
            order_id,
            fill_amount_in_ask_currency,
        ),
        OrdersVersion::V1 => calculate_fill_order_based_on_original_price(
            view,
            order_id,
            fill_amount_in_ask_currency,
        ),
    }
}

fn calculate_fill_order_based_on_remaining_balances(
    view: &impl OrdersAccountingView,
    order_id: OrderId,
    fill_amount_in_ask_currency: Amount,
) -> Result<Amount> {
    // Take remaining balances to calculate price
    let ask_balance = view.get_ask_balance(&order_id).map_err(|_| crate::Error::ViewFail)?;
    let give_balance = view.get_give_balance(&order_id).map_err(|_| crate::Error::ViewFail)?;

    ensure!(
        ask_balance >= fill_amount_in_ask_currency,
        Error::OrderOverbid(order_id, ask_balance, fill_amount_in_ask_currency)
    );

    calculate_filled_amount(ask_balance, give_balance, fill_amount_in_ask_currency)
        .ok_or(Error::OrderOverflow(order_id))
}

fn calculate_fill_order_based_on_original_price(
    view: &impl OrdersAccountingView,
    order_id: OrderId,
    fill_amount_in_ask_currency: Amount,
) -> Result<Amount> {
    // Take original balances to calculate price
    let order_data = view
        .get_order_data(&order_id)
        .map_err(|_| crate::Error::ViewFail)?
        .ok_or(crate::Error::OrderDataNotFound(order_id))?;

    let original_ask = crate::output_value_amount(order_data.ask())?;
    let original_give = crate::output_value_amount(order_data.give())?;

    // Check overbid anyway
    let current_ask_balance =
        view.get_ask_balance(&order_id).map_err(|_| crate::Error::ViewFail)?;
    ensure!(
        current_ask_balance >= fill_amount_in_ask_currency,
        Error::OrderOverbid(order_id, current_ask_balance, fill_amount_in_ask_currency)
    );

    let result = calculate_filled_amount(original_ask, original_give, fill_amount_in_ask_currency)
        .ok_or(Error::OrderOverflow(order_id))?;

    ensure!(
        result > Amount::ZERO,
        Error::OrderUnderbid(order_id, fill_amount_in_ask_currency)
    );

    Ok(result)
}

pub fn calculate_filled_amount(
    ask_amount: Amount,
    give_amount: Amount,
    fill_amount_in_ask_currency: Amount,
) -> Option<Amount> {
    let give = Uint256::from_u128(give_amount.into_atoms());
    let fill = Uint256::from_u128(fill_amount_in_ask_currency.into_atoms());
    let ask = Uint256::from_u128(ask_amount.into_atoms());

    let result = ((give * fill).expect("cannot overflow") / ask)?;
    let result: u128 = result.try_into().ok()?;

    Some(Amount::from_atoms(result))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use common::{
        chain::{output_value::OutputValue, tokens::TokenId, Destination, OrderData},
        primitives::H256,
    };
    use rstest::rstest;

    use crate::{InMemoryOrdersAccounting, OrdersAccountingDB};

    macro_rules! amount {
        ($value:expr) => {
            Amount::from_atoms($value)
        };
    }

    macro_rules! coin {
        ($value:expr) => {
            OutputValue::Coin(Amount::from_atoms($value))
        };
    }

    macro_rules! token {
        ($value:expr) => {
            OutputValue::TokenV1(TokenId::zero(), Amount::from_atoms($value))
        };
    }

    macro_rules! token2 {
        ($value:expr) => {
            OutputValue::TokenV1(H256::from_low_u64_be(1).into(), Amount::from_atoms($value))
        };
    }

    fn output_value_amount(value: &OutputValue) -> Amount {
        match value {
            OutputValue::Coin(amount) | OutputValue::TokenV1(_, amount) => *amount,
            OutputValue::TokenV0(_) => panic!("unsupported token"),
        }
    }

    #[rstest]
    #[case(0, 0, 0, None)]
    #[case(0, 1, 1, None)]
    #[case(0, u128::MAX, 1, None)]
    #[case(2, u128::MAX, 2, Some(u128::MAX))]
    #[case(1, 0, 0, Some(0))]
    #[case(1, 0, 1, Some(0))]
    #[case(1, 1, 1, Some(1))]
    #[case(1, 2, 1, Some(2))]
    #[case(2, 100, 0, Some(0))]
    #[case(2, 100, 1, Some(50))]
    #[case(2, 100, 2, Some(100))]
    #[case(3, 100, 0, Some(0))]
    #[case(3, 100, 1, Some(33))]
    #[case(3, 100, 2, Some(66))]
    #[case(3, 100, 3, Some(100))]
    fn calculate_filled_amount_impl_test(
        #[case] ask: u128,
        #[case] give: u128,
        #[case] fill: u128,
        #[case] result: Option<u128>,
    ) {
        assert_eq!(
            result.map(Amount::from_atoms),
            calculate_filled_amount(
                Amount::from_atoms(ask),
                Amount::from_atoms(give),
                Amount::from_atoms(fill)
            )
        );
    }

    #[rstest]
    #[case(token!(1), coin!(0), amount!(0), 0)]
    #[case(token!(1), coin!(0), amount!(1), 0)]
    #[case(token!(3), coin!(100), amount!(0), 0)]
    #[case(token!(3), coin!(100), amount!(1), 33)]
    #[case(token!(3), coin!(100), amount!(2), 66)]
    #[case(token!(3), coin!(100), amount!(3), 100)]
    #[case(token!(5), coin!(100), amount!(0), 0)]
    #[case(token!(5), coin!(100), amount!(1), 20)]
    #[case(token!(5), coin!(100), amount!(2), 40)]
    #[case(token!(5), coin!(100), amount!(3), 60)]
    #[case(token!(5), coin!(100), amount!(4), 80)]
    #[case(token!(5), coin!(100), amount!(5), 100)]
    #[case(coin!(100), token!(3), amount!(0), 0)]
    #[case(coin!(100), token!(3), amount!(1), 0)]
    #[case(coin!(100), token!(3), amount!(33), 0)]
    #[case(coin!(100), token!(3), amount!(34), 1)]
    #[case(coin!(100), token!(3), amount!(66), 1)]
    #[case(coin!(100), token!(3), amount!(67), 2)]
    #[case(coin!(100), token!(3), amount!(99), 2)]
    #[case(coin!(100), token!(3), amount!(100), 3)]
    #[case(token!(3), token2!(100), amount!(0), 0)]
    #[case(token!(3), token2!(100), amount!(1), 33)]
    #[case(token!(3), token2!(100), amount!(2), 66)]
    #[case(token!(3), token2!(100), amount!(3), 100)]
    #[case(coin!(3), coin!(100), amount!(0), 0)]
    #[case(coin!(3), coin!(100), amount!(1), 33)]
    #[case(coin!(3), coin!(100), amount!(2), 66)]
    #[case(coin!(3), coin!(100), amount!(3), 100)]
    #[case(coin!(1), token!(u128::MAX), amount!(1), u128::MAX)]
    #[case(coin!(2), token!(u128::MAX), amount!(2), u128::MAX)]
    fn fill_order_valid_values_v0(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: Amount,
        #[case] result: u128,
    ) {
        let order_id = OrderId::zero();

        // Original balances are irrelevant for price
        let orders_store = InMemoryOrdersAccounting::from_values(
            BTreeMap::from_iter([(
                order_id,
                OrderData::new(
                    Destination::AnyoneCanSpend,
                    OutputValue::Coin(Amount::ZERO),
                    OutputValue::Coin(Amount::ZERO),
                ),
            )]),
            BTreeMap::from_iter([(order_id, output_value_amount(&ask))]),
            BTreeMap::from_iter([(order_id, output_value_amount(&give))]),
        );
        let orders_db = OrdersAccountingDB::new(&orders_store);

        assert_eq!(
            calculate_fill_order_based_on_remaining_balances(&orders_db, order_id, fill),
            Ok(Amount::from_atoms(result))
        );
    }

    #[rstest]
    #[case(token!(3), coin!(100), amount!(1), 33)]
    #[case(token!(3), coin!(100), amount!(2), 66)]
    #[case(token!(3), coin!(100), amount!(3), 100)]
    #[case(token!(5), coin!(100), amount!(1), 20)]
    #[case(token!(5), coin!(100), amount!(2), 40)]
    #[case(token!(5), coin!(100), amount!(3), 60)]
    #[case(token!(5), coin!(100), amount!(4), 80)]
    #[case(token!(5), coin!(100), amount!(5), 100)]
    #[case(coin!(100), token!(3), amount!(34), 1)]
    #[case(coin!(100), token!(3), amount!(66), 1)]
    #[case(coin!(100), token!(3), amount!(67), 2)]
    #[case(coin!(100), token!(3), amount!(99), 2)]
    #[case(coin!(100), token!(3), amount!(100), 3)]
    #[case(token!(3), token2!(100), amount!(1), 33)]
    #[case(token!(3), token2!(100), amount!(2), 66)]
    #[case(token!(3), token2!(100), amount!(3), 100)]
    #[case(coin!(3), coin!(100), amount!(1), 33)]
    #[case(coin!(3), coin!(100), amount!(2), 66)]
    #[case(coin!(3), coin!(100), amount!(3), 100)]
    #[case(coin!(1), token!(u128::MAX), amount!(1), u128::MAX)]
    #[case(coin!(2), token!(u128::MAX), amount!(2), u128::MAX)]
    fn fill_order_valid_values_v1(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: Amount,
        #[case] result: u128,
    ) {
        let order_id = OrderId::zero();

        // Current balances are irrelevant for price
        let orders_store = InMemoryOrdersAccounting::from_values(
            BTreeMap::from_iter([(
                order_id,
                OrderData::new(Destination::AnyoneCanSpend, ask.clone(), give.clone()),
            )]),
            BTreeMap::from_iter([(order_id, fill)]),
            BTreeMap::from_iter([(order_id, Amount::ZERO)]),
        );
        let orders_db = OrdersAccountingDB::new(&orders_store);

        assert_eq!(
            calculate_fill_order_based_on_original_price(&orders_db, order_id, fill),
            Ok(Amount::from_atoms(result))
        );
    }

    #[rstest]
    #[case(token!(0), coin!(1), amount!(0), Error::OrderOverflow(OrderId::zero()))]
    #[case(token!(0), coin!(1), amount!(1), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(0), Amount::from_atoms(1)))]
    #[case(coin!(1), token!(1), amount!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    #[case(coin!(1), token!(u128::MAX), amount!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    fn fill_order_invalid_values_v0(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: Amount,
        #[case] error: Error,
    ) {
        let order_id = OrderId::zero();
        let orders_store = InMemoryOrdersAccounting::from_values(
            BTreeMap::from_iter([(
                order_id,
                OrderData::new(Destination::AnyoneCanSpend, ask.clone(), give.clone()),
            )]),
            BTreeMap::from_iter([(order_id, output_value_amount(&ask))]),
            BTreeMap::from_iter([(order_id, output_value_amount(&give))]),
        );
        let orders_db = OrdersAccountingDB::new(&orders_store);

        assert_eq!(
            calculate_fill_order_based_on_remaining_balances(&orders_db, order_id, fill),
            Err(error.clone())
        );
    }

    #[rstest]
    #[case(token!(0), coin!(1), amount!(0), Error::OrderOverflow(OrderId::zero()))]
    #[case(token!(0), coin!(1), amount!(1), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(0), Amount::from_atoms(1)))]
    #[case(coin!(1), token!(1), amount!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    #[case(coin!(1), token!(u128::MAX), amount!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    #[case(token!(3), coin!(1), amount!(0), Error::OrderUnderbid(OrderId::zero(), Amount::from_atoms(0)))]
    #[case(token!(3), coin!(1), amount!(1), Error::OrderUnderbid(OrderId::zero(), Amount::from_atoms(1)))]
    #[case(token!(3), coin!(1), amount!(2), Error::OrderUnderbid(OrderId::zero(), Amount::from_atoms(2)))]
    #[case(token!(1), coin!(0), amount!(0), Error::OrderUnderbid(OrderId::zero(), Amount::from_atoms(0)))]
    #[case(token!(1), coin!(0), amount!(1), Error::OrderUnderbid(OrderId::zero(), Amount::from_atoms(1)))]
    fn fill_order_invalid_values_v1(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: Amount,
        #[case] error: Error,
    ) {
        let order_id = OrderId::zero();
        let orders_store = InMemoryOrdersAccounting::from_values(
            BTreeMap::from_iter([(
                order_id,
                OrderData::new(Destination::AnyoneCanSpend, ask.clone(), give.clone()),
            )]),
            BTreeMap::from_iter([(order_id, output_value_amount(&ask))]),
            BTreeMap::from_iter([(order_id, output_value_amount(&give))]),
        );
        let orders_db = OrdersAccountingDB::new(&orders_store);

        assert_eq!(
            calculate_fill_order_based_on_original_price(&orders_db, order_id, fill),
            Err(error)
        );
    }
}
