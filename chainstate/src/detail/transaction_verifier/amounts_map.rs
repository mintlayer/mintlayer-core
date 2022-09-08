use std::collections::BTreeMap;

use common::{chain::tokens::TokensError, primitives::Amount};

use super::{error::ConnectTransactionError, tokens::CoinOrTokenId};

/// A temporary type used to accumulate token type vs amount
#[must_use]
pub struct AmountsMap {
    data: BTreeMap<CoinOrTokenId, Amount>,
}

impl AmountsMap {
    pub fn from_iter<T: IntoIterator<Item = (CoinOrTokenId, Amount)>>(
        iter: T,
    ) -> Result<Self, ConnectTransactionError> {
        let mut result = Self {
            data: BTreeMap::new(),
        };

        for (t, v) in iter {
            insert_or_increase(&mut result.data, t, v)?;
        }

        Ok(result)
    }

    pub fn consume(self) -> BTreeMap<CoinOrTokenId, Amount> {
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

            assert_eq!(
                AmountsMap::from_iter(
                    vec![
                        (t4, Amount::from_atoms(45)),
                        (t1, Amount::from_atoms(10)),
                        (t2, Amount::from_atoms(5)),
                        (t1, Amount::from_atoms(15)),
                        (t3, Amount::from_atoms(20)),
                        (t3, Amount::from_atoms(25)),
                        (t4, Amount::from_atoms(35)),
                    ]
                    .into_iter(),
                )
                .unwrap()
                .consume(),
                vec![
                    (t1, Amount::from_atoms(25)),
                    (t2, Amount::from_atoms(5)),
                    (t3, Amount::from_atoms(45)),
                    (t4, Amount::from_atoms(80))
                ]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
            );
        })
    }
}
