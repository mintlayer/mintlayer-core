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

use std::collections::BTreeMap;

use common::primitives::Amount;
use fallible_iterator::{FallibleIterator, IntoFallibleIterator};

use super::{
    error::{ConnectTransactionError, TokensError},
    token_issuance_cache::CoinOrTokenId,
};

/// A temporary type used to accumulate token type vs amount
#[derive(Debug)]
#[must_use]
pub struct AmountsMap {
    data: BTreeMap<CoinOrTokenId, Amount>,
}

impl AmountsMap {
    pub fn from_fallible_iter<
        T: IntoFallibleIterator<Item = (CoinOrTokenId, Amount), Error = ConnectTransactionError>,
    >(
        iter: T,
    ) -> Result<Self, ConnectTransactionError> {
        let mut result = Self {
            data: BTreeMap::new(),
        };

        iter.into_fallible_iter()
            .for_each(|(t, v)| insert_or_increase(&mut result.data, t, v).map_err(Into::into))?;

        Ok(result)
    }

    pub fn take(self) -> BTreeMap<CoinOrTokenId, Amount> {
        self.data
    }
}

fn insert_or_increase(
    total_amounts: &mut BTreeMap<CoinOrTokenId, Amount>,
    key: CoinOrTokenId,
    amount: Amount,
) -> Result<(), TokensError> {
    match total_amounts.get_mut(&key) {
        Some(value) => {
            *value = (*value + amount).ok_or(TokensError::CoinOrTokenOverflow)?;
        }
        None => {
            total_amounts.insert(key, amount);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::chain::tokens::TokenId;

    use super::*;

    #[test]
    fn basic() {
        utils::concurrency::model(|| {
            let t1 = CoinOrTokenId::Coin;
            let t2 = CoinOrTokenId::TokenId(TokenId::random());
            let t3 = CoinOrTokenId::TokenId(TokenId::random());
            let t4 = CoinOrTokenId::TokenId(TokenId::random());

            let data = fallible_iterator::convert(
                vec![
                    (t4, Amount::from_atoms(45)),
                    (t1, Amount::from_atoms(10)),
                    (t2, Amount::from_atoms(5)),
                    (t1, Amount::from_atoms(15)),
                    (t3, Amount::from_atoms(20)),
                    (t3, Amount::from_atoms(25)),
                    (t4, Amount::from_atoms(35)),
                ]
                .into_iter()
                .map(Ok),
            );

            let expected = vec![
                (t1, Amount::from_atoms(25)),
                (t2, Amount::from_atoms(5)),
                (t3, Amount::from_atoms(45)),
                (t4, Amount::from_atoms(80)),
            ];

            assert_eq!(
                AmountsMap::from_fallible_iter(data).unwrap().take(),
                expected.into_iter().collect::<BTreeMap<_, _>>()
            );
        })
    }

    #[test]
    fn with_error() {
        utils::concurrency::model(|| {
            let t1 = CoinOrTokenId::Coin;
            let t2 = CoinOrTokenId::TokenId(TokenId::random());
            let t3 = CoinOrTokenId::TokenId(TokenId::random());
            let t4 = CoinOrTokenId::TokenId(TokenId::random());

            let data = fallible_iterator::convert(
                vec![
                    (t4, Amount::from_atoms(45)),
                    (t1, Amount::from_atoms(10)),
                    (t2, Amount::from_atoms(5)),
                    (t1, Amount::from_atoms(15)),
                    (t3, Amount::from_atoms(20)),
                    (t3, Amount::from_atoms(25)),
                    (t4, Amount::from_atoms(35)),
                ]
                .into_iter()
                .map(Ok)
                .chain(vec![Err(
                    ConnectTransactionError::InvariantBrokenAlreadyUnspent,
                )]),
            );

            let expected = ConnectTransactionError::InvariantBrokenAlreadyUnspent;

            assert_eq!(AmountsMap::from_fallible_iter(data).unwrap_err(), expected);
        })
    }
}
