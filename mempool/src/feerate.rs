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

pub(crate) const INCREMENTAL_RELAY_FEE_RATE: FeeRate = FeeRate::new(Amount::from_atoms(1000));
pub(crate) const INCREMENTAL_RELAY_THRESHOLD: FeeRate = FeeRate::new(Amount::from_atoms(500));

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FeeRate {
    amount_per_kb: Amount,
}

impl FeeRate {
    pub(crate) const fn new(amount_per_kb: Amount) -> Self {
        Self { amount_per_kb }
    }

    pub(crate) fn from_total_tx_fee(
        total_tx_fee: Amount,
        tx_size: NonZeroUsize,
    ) -> Result<Self, TxValidationError> {
        let tx_size = u128::try_from(usize::from(tx_size)).expect("div_up conversion");
        Ok(Self {
            amount_per_kb: ((total_tx_fee * 1000).ok_or(TxValidationError::FeeOverflow)? / tx_size)
                .expect("tx_size nonzero"),
        })
    }

    pub(crate) fn compute_fee(&self, size: usize) -> Result<Amount, TxValidationError> {
        let size = u128::try_from(size).expect("compute_fee conversion");
        let fee = (self.amount_per_kb * size).ok_or(TxValidationError::FeeOverflow)?;
        // +999 for ceil operation
        let fee = (((fee + Amount::from_atoms(999)).ok_or(TxValidationError::FeeOverflow)?) / 1000)
            .expect("valid division");
        Ok(fee)
    }

    pub(crate) const fn atoms_per_kb(&self) -> u128 {
        self.amount_per_kb.into_atoms()
    }
}

impl std::ops::Add for FeeRate {
    type Output = Option<Self>;
    fn add(self, other: Self) -> Self::Output {
        (self.amount_per_kb + other.amount_per_kb).map(|amount_per_kb| FeeRate { amount_per_kb })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl std::ops::Div<NonZeroUsize> for FeeRate {
        type Output = FeeRate;
        fn div(self, rhs: NonZeroUsize) -> Self::Output {
            let rhs = u128::try_from(usize::from(rhs)).expect("conversion");
            FeeRate {
                amount_per_kb: (self.amount_per_kb / rhs).expect("rhs is nonzero"),
            }
        }
    }

    #[test]
    fn test_from_total_tx_fee() {
        let fee = Amount::from_atoms(7);
        let tx_size = usize::MAX;
        let rate = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap()).unwrap();
        assert_eq!(
            rate,
            FeeRate {
                amount_per_kb: Amount::from_atoms(0)
            }
        );

        let fee = Amount::from_atoms(u128::MAX);
        let tx_size = 1;
        let res = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap());
        assert!(matches!(res, Err(TxValidationError::FeeOverflow)));

        let fee = Amount::from_atoms(u128::MAX - 1);
        let tx_size = 3;
        let res = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap());
        assert!(matches!(res, Err(TxValidationError::FeeOverflow)));
    }
}
