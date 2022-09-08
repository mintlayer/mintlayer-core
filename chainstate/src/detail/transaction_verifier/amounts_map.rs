use std::collections::BTreeMap;

use common::{chain::tokens::TokensError, primitives::Amount};

use super::{error::ConnectTransactionError, tokens::CoinOrTokenId};

/// A temporary type used to accumulate token type vs amount
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

pub fn insert_or_increase(
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
