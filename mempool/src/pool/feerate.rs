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

use crate::error::MempoolPolicyError;

use super::fee::Fee;

pub const INCREMENTAL_RELAY_FEE_RATE: FeeRate = FeeRate::new(Amount::from_atoms(1000));
pub const INCREMENTAL_RELAY_THRESHOLD: FeeRate = FeeRate::new(Amount::from_atoms(500));

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate {
    amount_per_kb: Amount,
}

impl FeeRate {
    pub const fn new(amount_per_kb: Amount) -> Self {
        Self { amount_per_kb }
    }

    pub fn from_total_tx_fee(
        total_tx_fee: Fee,
        tx_size: NonZeroUsize,
    ) -> Result<Self, MempoolPolicyError> {
        let tx_size = u128::try_from(usize::from(tx_size)).expect("div_up conversion");
        let scaled_fee = (*total_tx_fee * 1000).ok_or(MempoolPolicyError::FeeOverflow)?;
        let amount_per_kb = (scaled_fee / tx_size).expect("tx_size nonzero");
        Ok(Self { amount_per_kb })
    }

    pub fn compute_fee(&self, size: usize) -> Result<Fee, MempoolPolicyError> {
        let size = u128::try_from(size).expect("compute_fee conversion");
        let fee = (self.amount_per_kb * size).ok_or(MempoolPolicyError::FeeOverflow)?;
        // +999 for ceil operation
        let ceil_add = Amount::from_atoms(999);
        let fee = (((fee + ceil_add).ok_or(MempoolPolicyError::FeeOverflow)?) / 1000)
            .expect("valid division");
        Ok(fee.into())
    }

    pub const fn atoms_per_kb(&self) -> u128 {
        self.amount_per_kb.into_atoms()
    }
}

impl std::ops::Add for FeeRate {
    type Output = Option<Self>;
    fn add(self, other: Self) -> Self::Output {
        (self.amount_per_kb + other.amount_per_kb).map(FeeRate::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl std::ops::Div<NonZeroUsize> for FeeRate {
        type Output = FeeRate;
        fn div(self, rhs: NonZeroUsize) -> Self::Output {
            let rhs = u128::try_from(usize::from(rhs)).expect("conversion");
            FeeRate { amount_per_kb: (self.amount_per_kb / rhs).expect("rhs is nonzero") }
        }
    }

    #[test]
    fn test_from_total_tx_fee() {
        let fee = Amount::from_atoms(7).into();
        let tx_size = usize::MAX;
        let rate = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap()).unwrap();
        assert_eq!(rate, FeeRate { amount_per_kb: Amount::from_atoms(0) });

        let fee = Amount::from_atoms(u128::MAX).into();
        let tx_size = 1;
        let res = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap());
        assert_eq!(res, Err(MempoolPolicyError::FeeOverflow));

        let fee = Amount::from_atoms(u128::MAX - 1).into();
        let tx_size = 3;
        let res = FeeRate::from_total_tx_fee(fee, NonZeroUsize::new(tx_size).unwrap());
        assert_eq!(res, Err(MempoolPolicyError::FeeOverflow));
    }
}
