// Copyright (c) 2024 RBB S.r.l
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

use crate::{
    chain::{ChainConfig, Currency},
    TokenDecimalsProvider, TokenDecimalsUnavailableError,
};

use super::{Amount, DecimalAmount, RpcAmountInSerde, RpcAmountOutSerde};

/// Amount type suitable for getting user input supporting both decimal and atom formats in Json.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct RpcAmountIn(RpcAmountInData);

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "RpcAmountInSerde", into = "RpcAmountInSerde")]
enum RpcAmountInData {
    Atoms(Amount),
    Decimal(DecimalAmount),
}

impl RpcAmountIn {
    /// Construct from atoms
    pub fn from_atoms(atoms: Amount) -> Self {
        Self(RpcAmountInData::Atoms(atoms))
    }

    /// Construct from decimal representation
    pub fn from_decimal(decimal: DecimalAmount) -> Self {
        Self(RpcAmountInData::Decimal(decimal))
    }

    /// Convert to amount using given number of decimals
    pub fn to_amount(self, decimals: u8) -> Option<Amount> {
        match self.0 {
            RpcAmountInData::Decimal(amount) => amount.to_amount(decimals),
            RpcAmountInData::Atoms(amount) => Some(amount),
        }
    }

    /// Check this is the same number presented in the same way
    pub fn is_same(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (RpcAmountInData::Decimal(a), RpcAmountInData::Decimal(b)) => a.is_same(b),
            (RpcAmountInData::Decimal(_), RpcAmountInData::Atoms(_)) => false,
            (RpcAmountInData::Atoms(_), RpcAmountInData::Decimal(_)) => false,
            (RpcAmountInData::Atoms(a), RpcAmountInData::Atoms(b)) => a == b,
        }
    }
}

impl From<Amount> for RpcAmountIn {
    fn from(value: Amount) -> Self {
        Self::from_atoms(value)
    }
}

impl From<DecimalAmount> for RpcAmountIn {
    fn from(value: DecimalAmount) -> Self {
        Self::from_decimal(value)
    }
}

impl From<RpcAmountInSerde> for RpcAmountInData {
    fn from(value: RpcAmountInSerde) -> Self {
        match value {
            RpcAmountInSerde::Atoms(atoms) => Self::Atoms(atoms.into()),
            RpcAmountInSerde::Decimal(decimals) => Self::Decimal(decimals.into()),
        }
    }
}

impl From<RpcAmountInData> for RpcAmountInSerde {
    fn from(value: RpcAmountInData) -> RpcAmountInSerde {
        match value {
            RpcAmountInData::Atoms(atoms) => RpcAmountInSerde::Atoms(atoms.into()),
            RpcAmountInData::Decimal(decimal) => RpcAmountInSerde::Decimal(decimal.into()),
        }
    }
}

/// Amount type suitable for presenting Amount to the user in Json format. It presents given amount
/// in both decimal and atom formats.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "RpcAmountOutSerde", into = "RpcAmountOutSerde")]
pub struct RpcAmountOut {
    atoms: Amount,
    decimal: DecimalAmount,
}

impl RpcAmountOut {
    pub const ZERO: Self = Self {
        atoms: Amount::ZERO,
        decimal: DecimalAmount::ZERO,
    };

    fn new_internal(atoms: Amount, decimal: DecimalAmount) -> Self {
        Self { atoms, decimal }
    }

    pub fn from_amount(amount: Amount, decimals: u8) -> Self {
        Self::from_amount_no_padding(amount, decimals)
    }

    pub fn from_currency_amount(
        amount: Amount,
        currency: &Currency,
        chain_config: &ChainConfig,
        token_decimals_provider: &impl TokenDecimalsProvider,
    ) -> Result<Self, TokenDecimalsUnavailableError> {
        let decimals = match currency {
            Currency::Coin => chain_config.coin_decimals(),
            Currency::Token(token_id) => token_decimals_provider.get_token_decimals(token_id)?.0,
        };
        Ok(Self::from_amount(amount, decimals))
    }

    /// Construct from amount, keeping all decimal digits
    pub fn from_amount_full_padding(amount: Amount, decimals: u8) -> Self {
        let decimal = DecimalAmount::from_amount_full_padding(amount, decimals);
        Self::new_internal(amount, decimal)
    }

    /// Construct from amount, keeping the minimal number of decimal places
    pub fn from_amount_no_padding(amount: Amount, decimals: u8) -> Self {
        let decimal = DecimalAmount::from_amount_no_padding(amount, decimals);
        Self::new_internal(amount, decimal)
    }

    pub fn amount(&self) -> Amount {
        self.atoms
    }

    pub fn decimal(&self) -> DecimalAmount {
        self.decimal
    }

    /// Check this is the same number presented in the same way
    pub fn is_same(&self, other: &Self) -> bool {
        self.atoms == other.atoms && self.decimal.is_same(&other.decimal)
    }
}

impl From<RpcAmountOutSerde> for RpcAmountOut {
    fn from(value: RpcAmountOutSerde) -> Self {
        let RpcAmountOutSerde { atoms, decimal } = value;
        Self {
            atoms: atoms.into(),
            decimal: decimal.into(),
        }
    }
}

impl From<RpcAmountOut> for RpcAmountOutSerde {
    fn from(value: RpcAmountOut) -> RpcAmountOutSerde {
        let RpcAmountOut { atoms, decimal } = value;
        Self {
            atoms: atoms.into(),
            decimal: decimal.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::zero(0, 0)]
    #[case(123456, 0)]
    #[case(123450, 1)]
    #[case(123450, 2)]
    #[case(123450, 9)]
    #[case(4000000000, 3)]
    #[case(1u128 << 55, 17)]
    #[case(u128::MAX, 0)]
    #[case(u128::MAX, 1)]
    #[case(u128::MAX, 25)]
    fn rpc_amount_serde(#[case] atoms: u128, #[case] n_decimals: u8) {
        let atoms = Amount::from_atoms(atoms);
        let decimal = DecimalAmount::from_amount_no_padding(atoms, n_decimals);

        let decimal_str = decimal.to_string();
        let atoms_str = atoms.into_atoms().to_string();

        assert!(!atoms_str.contains('.'));

        let decimal_in = RpcAmountIn::from_decimal(decimal);
        let decimal_in_json = json!({ "decimal": decimal_str });
        assert_eq!(serde_json::to_value(decimal_in).unwrap(), decimal_in_json);
        assert!(decimal_in.is_same(&serde_json::from_value(decimal_in_json).unwrap()));

        let atoms_in = RpcAmountIn::from_atoms(atoms);
        let atoms_in_json = json!({ "atoms": atoms_str });
        assert_eq!(serde_json::to_value(atoms_in).unwrap(), atoms_in_json);
        assert!(atoms_in.is_same(&serde_json::from_value(atoms_in_json).unwrap()));

        let rpc_out = RpcAmountOut::from_amount_no_padding(atoms, n_decimals);
        let rpc_out_json = json!({ "atoms": atoms_str, "decimal": decimal_str });
        assert_eq!(serde_json::to_value(&rpc_out).unwrap(), rpc_out_json);
        assert!(rpc_out.is_same(&serde_json::from_value(rpc_out_json).unwrap()));
    }

    #[test]
    fn not_both_in() {
        let amt_json = json!({"atoms": "0", "decimal": "0"});
        assert!(serde_json::from_value::<RpcAmountIn>(amt_json).is_err());
    }
}
