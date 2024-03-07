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

use rpc_description::{HasValueHint, ValueHint as VH};

use super::{Amount, DecimalAmount};

/// Amount type suitable for getting user input supporting both decimal and atom formats in Json.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcAmountIn(RpcAmountData);

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, HasValueHint)]
#[serde(untagged)]
enum RpcAmountData {
    Decimal(DecimalAmount),
    Atoms(Amount),
}

impl RpcAmountIn {
    /// Construct from atoms
    pub fn from_atoms(atoms: Amount) -> Self {
        Self(RpcAmountData::Atoms(atoms))
    }

    /// Construct from decimal representation
    pub fn from_decimal(decimal: DecimalAmount) -> Self {
        Self(RpcAmountData::Decimal(decimal))
    }

    /// Convert to amount using given number of decimals
    pub fn to_amount(self, decimals: u8) -> Option<Amount> {
        match self.0 {
            RpcAmountData::Decimal(amount) => amount.to_amount(decimals),
            RpcAmountData::Atoms(amount) => Some(amount),
        }
    }

    /// Check this is the same number presented in the same way
    pub fn is_same(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (RpcAmountData::Decimal(a), RpcAmountData::Decimal(b)) => a.is_same(b),
            (RpcAmountData::Decimal(_), RpcAmountData::Atoms(_)) => false,
            (RpcAmountData::Atoms(_), RpcAmountData::Decimal(_)) => false,
            (RpcAmountData::Atoms(a), RpcAmountData::Atoms(b)) => a == b,
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

/// Amount type suitable for presenting Amount to the user in Json format. It presents given amount
/// in both decimal and atom formats.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RpcAmountOut {
    #[serde(flatten)]
    atoms: Amount,

    #[serde(flatten)]
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
        Self::from_amount_minimal(amount, decimals)
    }

    /// Construct from amount, keeping all decimal digits
    pub fn from_amount_full(amount: Amount, decimals: u8) -> Self {
        let decimal = DecimalAmount::from_amount_full(amount, decimals);
        Self::new_internal(amount, decimal)
    }

    /// Construct from amount, keeping the minimal number of decimal places
    pub fn from_amount_minimal(amount: Amount, decimals: u8) -> Self {
        let decimal = DecimalAmount::from_amount_minimal(amount, decimals);
        Self::new_internal(amount, decimal)
    }

    pub fn amount(&self) -> Amount {
        self.atoms
    }

    pub fn decimal(&self) -> DecimalAmount {
        self.decimal
    }
}

impl HasValueHint for RpcAmountOut {
    const HINT: VH = VH::Object(&[("atoms", &VH::NUMBER_STRING), ("decimal", &VH::DECIMAL_STRING)]);
}
