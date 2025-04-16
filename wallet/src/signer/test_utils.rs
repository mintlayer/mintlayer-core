// Copyright (c) 2021-2025 RBB S.r.l
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

use common::{chain::output_value::OutputValue, primitives::Amount};
use randomness::Rng;
use wallet_types::{partially_signed_transaction::OrderAdditionalInfo, Currency};

pub fn random_order_info(
    ask_currency: &Currency,
    give_currency: &Currency,
    rng: &mut impl Rng,
) -> OrderAdditionalInfo {
    OrderAdditionalInfo {
        initially_asked: random_output_value(ask_currency, rng),
        initially_given: random_output_value(give_currency, rng),
        ask_balance: Amount::from_atoms(rng.gen()),
        give_balance: Amount::from_atoms(rng.gen()),
    }
}

pub fn random_output_value(currency: &Currency, rng: &mut impl Rng) -> OutputValue {
    match currency {
        Currency::Coin => OutputValue::Coin(Amount::from_atoms(rng.gen())),
        Currency::Token(id) => OutputValue::TokenV1(*id, Amount::from_atoms(rng.gen())),
    }
}
