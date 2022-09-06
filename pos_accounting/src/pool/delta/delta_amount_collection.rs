use std::{collections::BTreeMap, ops::Neg};

use common::primitives::{signed_amount::SignedAmount, Amount};

use serialization::{Decode, Encode};

use crate::error::Error;

#[derive(Clone, Encode, Decode)]
pub struct DeltaAmountCollection<K: Ord> {
    data: BTreeMap<K, SignedAmount>,
}

impl<K: Ord> DeltaAmountCollection<K> {
    pub fn merge_delta_amounts(&mut self, delta_to_apply: Self) -> Result<(), Error> {
        delta_to_apply.data.into_iter().try_for_each(|(key, other_amount)| {
            Self::merge_delta_amount_element(&mut self.data, key, other_amount)
        })?;

        Ok(())
    }

    /// Undo a merge with a delta of a balance; notice that we don't need undo data for this, since we can just flip the sign of the amount
    pub fn undo_merge_delta_amounts(&mut self, delta_to_remove: Self) -> Result<(), Error> {
        delta_to_remove.data.into_iter().try_for_each(|(key, other_amount)| {
            Self::merge_delta_amount_element(
                &mut self.data,
                key,
                (-other_amount).ok_or(Error::DeltaUndoNegationError)?,
            )
        })?;

        Ok(())
    }

    fn merge_delta_amount_element(
        map: &mut BTreeMap<K, SignedAmount>,
        key: K,
        other_amount: SignedAmount,
    ) -> Result<(), Error> {
        let current = map.get(&key);
        let new_bal = Self::combine_signed_amount_delta(&current.copied(), other_amount)?;
        if new_bal == SignedAmount::ZERO {
            // if the new amount is zero, no need to have it at all since it has no effect
            map.remove(&key);
        } else {
            map.insert(key, new_bal);
        }
        Ok(())
    }

    fn combine_signed_amount_delta(
        lhs: &Option<SignedAmount>,
        rhs: SignedAmount,
    ) -> Result<SignedAmount, Error> {
        match lhs {
            None => Ok(rhs),
            Some(v1) => {
                let sum = (*v1 + rhs).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
                Ok(sum)
            }
        }
    }

    pub fn add_signed(&mut self, id: K, to_add: SignedAmount) -> Result<(), Error> {
        match self.data.entry(id) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(to_add);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let current_amount = e.get();
                let new_amount = (*current_amount + to_add).ok_or(Error::AdditionError)?;
                if new_amount != SignedAmount::ZERO {
                    let _ = e.insert(new_amount);
                } else {
                    let _ = e.remove();
                }
            }
        }
        Ok(())
    }

    pub fn add_unsigned(&mut self, id: K, to_add: Amount) -> Result<(), Error> {
        let signed_amount_to_add =
            to_add.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
        self.add_signed(id, signed_amount_to_add)
    }

    pub fn sub_unsigned(&mut self, id: K, to_sub: Amount) -> Result<(), Error> {
        let signed_amount_to_sub = to_sub
            .into_signed()
            .ok_or(Error::ArithmeticErrorToSignedFailed)?
            .neg()
            .ok_or(Error::ArithmeticErrorToSignedFailed)?;
        self.add_signed(id, signed_amount_to_sub)
    }

    pub fn data(&self) -> &BTreeMap<K, SignedAmount> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<K, SignedAmount> {
        self.data
    }
}

impl<K: Ord> Default for DeltaAmountCollection<K> {
    fn default() -> Self {
        Self {
            data: Default::default(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_add_empty() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::new(),
        };
        collection.add_signed(1, SignedAmount::from_atoms(1)).unwrap();
        assert_eq!(collection.data.len(), 1);
        assert_eq!(
            collection.data.get(&1).unwrap(),
            &SignedAmount::from_atoms(1)
        )
    }

    #[test]
    fn test_add_existing() {
        // 1 add 1 = 2
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(1))]),
        };

        collection.add_signed(1, SignedAmount::from_atoms(1)).unwrap();
        assert_eq!(collection.data.len(), 1);
        assert_eq!(
            collection.data.get(&1).unwrap(),
            &SignedAmount::from_atoms(2)
        )
    }

    #[test]
    fn test_add_neg_existing() {
        // 2 add -1 = 1
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(2))]),
        };

        collection.add_signed(1, SignedAmount::from_atoms(-1)).unwrap();
        assert_eq!(collection.data.len(), 1);
        assert_eq!(
            collection.data.get(&1).unwrap(),
            &SignedAmount::from_atoms(1)
        )
    }

    #[test]
    fn test_add_with_other() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([
                (1, SignedAmount::from_atoms(1)),
                (2, SignedAmount::from_atoms(3)),
            ]),
        };

        collection.add_signed(1, SignedAmount::from_atoms(1)).unwrap();
        let expected_data =
            BTreeMap::from([(1, SignedAmount::from_atoms(2)), (2, SignedAmount::from_atoms(3))]);
        assert_eq!(collection.data, expected_data);
    }

    #[test]
    fn test_add_zero_sum() {
        // 1 add -1 = remove
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(1))]),
        };

        collection.add_signed(1, SignedAmount::from_atoms(-1)).unwrap();
        assert!(collection.data.is_empty());
    }

    #[test]
    fn test_add_overflow() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::MAX)]),
        };

        let res = collection.add_signed(1, SignedAmount::from_atoms(1));
        assert_eq!(res, Err(Error::AdditionError));
    }

    #[test]
    fn test_add_underflow() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::MIN)]),
        };

        let res = collection.add_signed(1, SignedAmount::from_atoms(-1));
        assert_eq!(res, Err(Error::AdditionError));
    }

    #[test]
    fn test_add_unsign() {
        // 1 add 1 = 2
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(1))]),
        };

        collection.add_unsigned(1, Amount::from_atoms(1)).unwrap();
        assert_eq!(collection.data.len(), 1);
        assert_eq!(
            collection.data.get(&1).unwrap(),
            &SignedAmount::from_atoms(2)
        )
    }

    #[test]
    fn test_add_unsign_overflow() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(2))]),
        };

        let res = collection.add_unsigned(1, Amount::MAX);
        assert_eq!(res, Err(Error::ArithmeticErrorToSignedFailed));
    }

    #[test]
    fn test_sub_existing() {
        // 2 sub 1 = 1
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(2))]),
        };

        collection.sub_unsigned(1, Amount::from_atoms(1)).unwrap();
        assert_eq!(collection.data.len(), 1);
        assert_eq!(
            collection.data.get(&1).unwrap(),
            &SignedAmount::from_atoms(1)
        )
    }

    #[test]
    fn test_sub_zero_sum() {
        // 1 sub 1 = remove
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(1))]),
        };

        collection.sub_unsigned(1, Amount::from_atoms(1)).unwrap();
        assert!(collection.data.is_empty());
    }

    #[test]
    fn test_sub_unsigned_underflow() {
        let mut collection = DeltaAmountCollection {
            data: BTreeMap::from([(1, SignedAmount::from_atoms(2))]),
        };

        let res = collection.sub_unsigned(1, Amount::MAX);
        assert_eq!(res, Err(Error::ArithmeticErrorToSignedFailed));
    }

    #[test]
    fn test_merge_collections() {
        let mut collection1 = DeltaAmountCollection {
            data: BTreeMap::from([
                (1, SignedAmount::from_atoms(1)),
                (2, SignedAmount::from_atoms(2)),
                (3, SignedAmount::from_atoms(2)),
                (4, SignedAmount::from_atoms(2)),
            ]),
        };
        let collection1_origin = collection1.clone();

        let collection2 = DeltaAmountCollection {
            data: BTreeMap::from([
                (1, SignedAmount::from_atoms(-1)),
                (2, SignedAmount::from_atoms(2)),
                (3, SignedAmount::from_atoms(-3)),
                (5, SignedAmount::from_atoms(2)),
            ]),
        };
        let collection2_clone = collection2.clone();

        let expected_data = BTreeMap::from([
            (2, SignedAmount::from_atoms(4)),
            (3, SignedAmount::from_atoms(-1)),
            (4, SignedAmount::from_atoms(2)),
            (5, SignedAmount::from_atoms(2)),
        ]);

        collection1.merge_delta_amounts(collection2).unwrap();
        assert_eq!(collection1.data, expected_data);

        collection1.undo_merge_delta_amounts(collection2_clone).unwrap();
        assert_eq!(collection1.data, collection1_origin.data);
    }
}
