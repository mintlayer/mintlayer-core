// Copyright (c) 2021-2022 RBB S.r.l
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

use std::num::NonZeroUsize;

use common::primitives::amount::Amount;

use crate::error::TxValidationError;

lazy_static::lazy_static! {
    pub(crate) static ref INCREMENTAL_RELAY_FEE_RATE: FeeRate = FeeRate::new(Amount::from_atoms(1000));
    pub(crate) static ref INCREMENTAL_RELAY_THRESHOLD: FeeRate = FeeRate::new(Amount::from_atoms(500));
}

// TODO we should reconsider using Amount and define functions for the specific operations required
// on FeeRate. Previous attempts to do this did not pan out, but this should be revisited to avoid
// dangerous arithmetic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FeeRate {
    atoms_per_kb: u128,
}

impl FeeRate {
    pub(crate) fn new(atoms_per_kb: Amount) -> Self {
        Self {
            atoms_per_kb: atoms_per_kb.into_atoms(),
        }
    }

    pub(crate) fn from_total_tx_fee(
        total_tx_fee: Amount,
        tx_size: NonZeroUsize,
    ) -> Result<Self, TxValidationError> {
        Ok(Self {
            atoms_per_kb: Self::div_up(
                (total_tx_fee * 1000).ok_or(TxValidationError::FeeOverflow)?,
                tx_size,
            )
            .into_atoms(),
        })
    }

    pub(crate) fn compute_fee(&self, size: usize) -> Amount {
        let size = u128::try_from(size).expect("compute_fee conversion");
        // +999 for ceil operation
        Amount::from_atoms((self.atoms_per_kb * size + 999) / 1000)
    }

    pub(crate) fn atoms_per_kb(&self) -> u128 {
        self.atoms_per_kb
    }

    // TODO Use NonZeroUsize for divisor
    fn div_up(dividend: Amount, divisor: NonZeroUsize) -> Amount {
        let divisor = u128::try_from(usize::from(divisor)).expect("div_up conversion");
        if divisor == 1 {
            dividend
        } else if (dividend % divisor).expect("divisor is nonzero") == Amount::from_atoms(0) {
            (dividend / divisor).expect("divisor is nonzero")
        } else {
            ((dividend / divisor).expect("divisor is nonzero") + Amount::from_atoms(1))
                .expect("should not overflow")
        }
    }
}

impl std::ops::Add for FeeRate {
    type Output = FeeRate;
    fn add(self, other: Self) -> Self::Output {
        let atoms_per_kb = self.atoms_per_kb + other.atoms_per_kb;
        FeeRate { atoms_per_kb }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU128;

    impl std::ops::Div<NonZeroU128> for FeeRate {
        type Output = FeeRate;
        fn div(self, rhs: NonZeroU128) -> Self::Output {
            FeeRate {
                atoms_per_kb: self.atoms_per_kb / rhs,
            }
        }
    }

    #[test]
    fn test_div_up() {
        let fee = Amount::from_atoms(7);
        let tx_size = usize::MAX;
        let rate = FeeRate::div_up(fee, NonZeroUsize::new(tx_size).unwrap());
        assert_eq!(rate, Amount::from_atoms(1));

        let fee = Amount::from_atoms(u128::MAX);
        let tx_size = 1;
        let rate = FeeRate::div_up(fee, NonZeroUsize::new(tx_size).unwrap());
        assert_eq!(rate, Amount::from_atoms(u128::MAX));

        let fee = Amount::from_atoms(u128::MAX - 1);
        let tx_size = 3;
        let rate = FeeRate::div_up(fee, NonZeroUsize::new(tx_size).unwrap());
        assert_eq!(
            rate,
            ((fee / tx_size.try_into().unwrap()).unwrap() + Amount::from_atoms(1)).unwrap()
        );
    }
}
