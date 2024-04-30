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
        let ask_balance = match order_data.ask {
            OutputValue::Coin(_) => OutputValue::Coin(ask_balance),
            OutputValue::TokenV0(_) => return Err(Error::UnsupportedTokenVersion),
            OutputValue::TokenV1(token_id, _) => OutputValue::TokenV1(token_id, ask_balance),
        };

        // FIXME: fill > ask_balance should be possible
        ensure_currencies_and_amounts_match(order_id, &ask_balance, fill_value)?;
    }

    calculate_filled_amount_impl(ask_balance, give_balance, fill_value.amount())
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
            ensure!(amount1 >= amount2, Error::OrderOverflow(order_id));
            Ok(())
        }
        (OutputValue::TokenV1(id1, amount1), OutputValue::TokenV1(id2, amount2)) => {
            ensure!(amount1 >= amount2, Error::OrderOverflow(order_id));
            ensure!(id1 == id2, Error::CurrencyMismatch);
            Ok(())
        }
        (OutputValue::Coin(_), OutputValue::TokenV1(_, _))
        | (OutputValue::TokenV1(_, _), OutputValue::Coin(_)) => Err(Error::CurrencyMismatch),
        (OutputValue::TokenV0(_), _) | (_, OutputValue::TokenV0(_)) => {
            Err(Error::UnsupportedTokenVersion)
        }
    }
}

// FIXME: tests
