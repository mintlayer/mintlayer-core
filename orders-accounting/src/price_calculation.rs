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
    chain::{output_value::OutputValue, OrderId},
    primitives::Amount,
};
use utils::ensure;

use crate::{error::Result, Error, OrdersAccountingView};

pub fn calculate_fill_order(
    view: &impl OrdersAccountingView,
    order_id: OrderId,
    fill_value: &OutputValue,
) -> Result<Amount> {
    let order_data = view
        .get_order_data(&order_id)
        .map_err(|_| crate::Error::ViewFail)?
        .ok_or(Error::OrderDataNotFound(order_id))?;
    let ask_balance = view
        .get_ask_balance(&order_id)
        .map_err(|_| crate::Error::ViewFail)?
        .ok_or(Error::OrderAskBalanceNotFound(order_id))?;
    let give_balance = view
        .get_give_balance(&order_id)
        .map_err(|_| crate::Error::ViewFail)?
        .ok_or(Error::OrderGiveBalanceNotFound(order_id))?;

    {
        let ask_balance = match order_data.ask() {
            OutputValue::Coin(_) => OutputValue::Coin(ask_balance),
            OutputValue::TokenV0(_) => return Err(Error::UnsupportedTokenVersion),
            OutputValue::TokenV1(token_id, _) => OutputValue::TokenV1(*token_id, ask_balance),
        };

        ensure_currencies_and_amounts_match(order_id, &ask_balance, fill_value)?;
    }

    let fill_amount = match fill_value {
        OutputValue::Coin(amount) | OutputValue::TokenV1(_, amount) => *amount,
        OutputValue::TokenV0(_) => return Err(Error::UnsupportedTokenVersion),
    };

    calculate_filled_amount_impl(ask_balance, give_balance, fill_amount)
        .ok_or(Error::OrderOverflow(order_id))
}

fn calculate_filled_amount_impl(ask: Amount, give: Amount, fill: Amount) -> Option<Amount> {
    (give * fill.into_atoms()).and_then(|v| v / ask.into_atoms())
}

fn ensure_currencies_and_amounts_match(
    order_id: OrderId,
    left: &OutputValue,
    right: &OutputValue,
) -> Result<()> {
    match (left, right) {
        (OutputValue::Coin(amount1), OutputValue::Coin(amount2)) => {
            ensure!(
                amount1 >= amount2,
                Error::OrderOverbid(order_id, *amount1, *amount2)
            );
            Ok(())
        }
        (OutputValue::TokenV1(id1, amount1), OutputValue::TokenV1(id2, amount2)) => {
            ensure!(
                amount1 >= amount2,
                Error::OrderOverbid(order_id, *amount1, *amount2)
            );
            ensure!(id1 == id2, Error::CurrencyMismatch);
            Ok(())
        }
        (OutputValue::Coin(_), OutputValue::TokenV1(_, _))
        | (OutputValue::TokenV1(_, _), OutputValue::Coin(_)) => Err(Error::CurrencyMismatch),
        (OutputValue::TokenV0(_), _) | (_, OutputValue::TokenV0(_)) => {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use common::{
        chain::{tokens::TokenId, Destination, OrderData},
        primitives::H256,
    };
    use rstest::rstest;

    use crate::{InMemoryOrdersAccounting, OrdersAccountingDB};

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
    #[case(3, u128::MAX, 2, None)]
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
            calculate_filled_amount_impl(
                Amount::from_atoms(ask),
                Amount::from_atoms(give),
                Amount::from_atoms(fill)
            )
        );
    }

    #[rstest]
    #[case(token!(1), coin!(0), token!(0), 0)]
    #[case(token!(1), coin!(0), token!(1), 0)]
    #[case(token!(3), coin!(100), token!(0), 0)]
    #[case(token!(3), coin!(100), token!(1), 33)]
    #[case(token!(3), coin!(100), token!(2), 66)]
    #[case(token!(3), coin!(100), token!(3), 100)]
    #[case(token!(5), coin!(100), token!(0), 0)]
    #[case(token!(5), coin!(100), token!(1), 20)]
    #[case(token!(5), coin!(100), token!(2), 40)]
    #[case(token!(5), coin!(100), token!(3), 60)]
    #[case(token!(5), coin!(100), token!(4), 80)]
    #[case(token!(5), coin!(100), token!(5), 100)]
    #[case(coin!(100), token!(3), coin!(0), 0)]
    #[case(coin!(100), token!(3), coin!(1), 0)]
    #[case(coin!(100), token!(3), coin!(33), 0)]
    #[case(coin!(100), token!(3), coin!(34), 1)]
    #[case(coin!(100), token!(3), coin!(66), 1)]
    #[case(coin!(100), token!(3), coin!(67), 2)]
    #[case(coin!(100), token!(3), coin!(99), 2)]
    #[case(coin!(100), token!(3), coin!(100), 3)]
    #[case(token!(3), token2!(100), token!(0), 0)]
    #[case(token!(3), token2!(100), token!(1), 33)]
    #[case(token!(3), token2!(100), token!(2), 66)]
    #[case(token!(3), token2!(100), token!(3), 100)]
    #[case(coin!(3), coin!(100), coin!(0), 0)]
    #[case(coin!(3), coin!(100), coin!(1), 33)]
    #[case(coin!(3), coin!(100), coin!(2), 66)]
    #[case(coin!(3), coin!(100), coin!(3), 100)]
    #[case(coin!(1), token!(u128::MAX), coin!(1), u128::MAX)]
    fn fill_order_valid_values(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: OutputValue,
        #[case] result: u128,
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
            calculate_fill_order(&orders_db, order_id, &fill),
            Ok(Amount::from_atoms(result))
        );
    }

    #[rstest]
    #[case(token!(0), coin!(1), token!(0), Error::OrderOverflow(OrderId::zero()))]
    #[case(token!(0), coin!(1), token!(1), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(0), Amount::from_atoms(1)))]
    #[case(coin!(1), token!(1), coin!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    #[case(coin!(1), token!(u128::MAX), coin!(2), Error::OrderOverbid(OrderId::zero(), Amount::from_atoms(1), Amount::from_atoms(2)))]
    #[case(coin!(2), token!(u128::MAX), coin!(2), Error::OrderOverflow(OrderId::zero()))]
    #[case(coin!(1), token!(1), token!(1), Error::CurrencyMismatch)]
    #[case(coin!(1), token!(1), token!(1), Error::CurrencyMismatch)]
    #[case(token!(1), token2!(1), token2!(1), Error::CurrencyMismatch)]
    fn fill_order_invalid_values(
        #[case] ask: OutputValue,
        #[case] give: OutputValue,
        #[case] fill: OutputValue,
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
            calculate_fill_order(&orders_db, order_id, &fill),
            Err(error)
        );
    }
}
