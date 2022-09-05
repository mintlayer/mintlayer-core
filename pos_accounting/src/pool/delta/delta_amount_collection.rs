use std::collections::BTreeMap;

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

    pub fn sub_signed(&mut self, id: K, to_sub: SignedAmount) -> Result<(), Error> {
        match self.data.entry(id) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(to_sub);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let current_amount = e.get();
                let new_amount = (*current_amount - to_sub).ok_or(Error::SubError)?;
                if new_amount != SignedAmount::ZERO {
                    let _ = e.insert(new_amount);
                } else {
                    let _ = e.remove();
                }
            }
        }
        Ok(())
    }

    pub fn sub_unsigned(&mut self, id: K, to_sub: Amount) -> Result<(), Error> {
        let signed_amount_to_sub =
            to_sub.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
        self.sub_signed(id, signed_amount_to_sub)
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
