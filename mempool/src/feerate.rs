use std::num::NonZeroU128;

use common::primitives::amount::Amount;

lazy_static::lazy_static! {
    pub(crate) static ref INCREMENTAL_RELAY_FEE_RATE: FeeRate = FeeRate::new(Amount::from_atoms(1000));
    pub(crate) static ref INCREMENTAL_RELAY_THRESHOLD: FeeRate = FeeRate::new(Amount::from_atoms(500));
}

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

    pub(crate) fn of_tx(fee: Amount, tx_size: usize) -> Self {
        Self {
            atoms_per_kb: Self::div_up(1000 * fee.into_atoms(), tx_size),
        }
    }

    pub(crate) fn compute_fee(&self, size: usize) -> Amount {
        let size = u128::try_from(size).expect("compute_fee conversion");
        Amount::from_atoms(self.atoms_per_kb * size / 1000)
    }

    pub(crate) fn atoms_per_kb(&self) -> u128 {
        self.atoms_per_kb
    }

    fn div_up(fee: u128, tx_size: usize) -> u128 {
        let tx_size = u128::try_from(tx_size).expect("div_up conversion");
        (fee + tx_size - 1) / tx_size
    }
}

impl std::ops::Add for FeeRate {
    type Output = FeeRate;
    fn add(self, other: Self) -> Self::Output {
        let atoms_per_kb = self.atoms_per_kb + other.atoms_per_kb;
        FeeRate { atoms_per_kb }
    }
}

impl std::ops::Div<NonZeroU128> for FeeRate {
    type Output = FeeRate;
    fn div(self, rhs: NonZeroU128) -> Self::Output {
        FeeRate {
            atoms_per_kb: self.atoms_per_kb / rhs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_div_up() {
        let fee = 7;
        let tx_size = usize::MAX;
        let rate = FeeRate::div_up(fee, tx_size);
        assert_eq!(rate, 1);
    }
}
