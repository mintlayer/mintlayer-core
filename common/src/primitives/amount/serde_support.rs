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

use serde::de::Error;

use rpc_description::{HasValueHint, ValueHint as VH};

use super::{Amount, DecimalAmount, UnsignedIntType as UInt};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum StringOrUInt {
    String(String),
    UInt(UInt),
}

/// Atom-based string or int
pub struct AtomsInner(Amount);

impl serde::Serialize for AtomsInner {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.atoms.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AtomsInner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let atoms = match StringOrUInt::deserialize(deserializer)? {
            StringOrUInt::String(s) => s.parse().map_err(D::Error::custom)?,
            StringOrUInt::UInt(u) => u,
        };
        Ok(Self(Amount::from_atoms(atoms)))
    }
}

impl From<Amount> for AtomsInner {
    fn from(value: Amount) -> Self {
        Self(value)
    }
}

impl From<AtomsInner> for Amount {
    fn from(value: AtomsInner) -> Self {
        value.0
    }
}

/// Decimal string or int
pub struct DecimalInner(DecimalAmount);

impl serde::Serialize for DecimalInner {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DecimalInner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let decimal = match StringOrUInt::deserialize(deserializer)? {
            StringOrUInt::String(s) => s.parse().map_err(D::Error::custom)?,
            StringOrUInt::UInt(u) => DecimalAmount::from_uint_integral(u),
        };
        Ok(Self(decimal))
    }
}

impl From<DecimalAmount> for DecimalInner {
    fn from(value: DecimalAmount) -> Self {
        Self(value)
    }
}

impl From<DecimalInner> for DecimalAmount {
    fn from(value: DecimalInner) -> Self {
        value.0
    }
}

#[derive(serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct AmountSerde {
    pub atoms: AtomsInner,
}

#[derive(serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcAmountOutSerde {
    pub atoms: AtomsInner,
    pub decimal: DecimalInner,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcAmountInSerde {
    Atoms(AtomsInner),
    Decimal(DecimalInner),
}

impl HasValueHint for RpcAmountInSerde {
    const HINT_SER: VH = VH::Choice(&[
        &VH::Object(&[("atoms", &AtomsInner::HINT_SER)]),
        &VH::Object(&[("decimal", &DecimalInner::HINT_SER)]),
    ]);
}

rpc_description::impl_value_hint!({
    AtomsInner => VH::NUMBER_STRING;
    DecimalInner => VH::DECIMAL_STRING;
    Amount => AmountSerde::HINT_SER;
    super::RpcAmountIn => RpcAmountInSerde::HINT_SER;
    super::RpcAmountOut => RpcAmountOutSerde::HINT_SER;
});
