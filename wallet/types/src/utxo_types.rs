// Copyright (c) 2023 RBB S.r.l
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

use common::chain::TxOutput;

use crate::wallet_tx::TxState;

pub type UtxoTypeInt = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum UtxoType {
    Transfer = 1 << 0,
    LockThenTransfer = 1 << 1,
    CreateStakePool = 1 << 2,
    ProduceBlockFromStake = 1 << 4,
    IssueNft = 1 << 7,
    Htlc = 1 << 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum UtxoState {
    Confirmed = 1 << 0,
    InMempool = 1 << 1,
    Conflicted = 1 << 2,
    Inactive = 1 << 3,
    Abandoned = 1 << 4,
}

pub fn get_utxo_type(output: &TxOutput) -> Option<UtxoType> {
    match output {
        TxOutput::Transfer(_, _) => Some(UtxoType::Transfer),
        TxOutput::LockThenTransfer(_, _, _) => Some(UtxoType::LockThenTransfer),
        TxOutput::CreateStakePool(_, _) => Some(UtxoType::CreateStakePool),
        TxOutput::ProduceBlockFromStake(_, _) => Some(UtxoType::ProduceBlockFromStake),
        TxOutput::IssueNft(_, _, _) => Some(UtxoType::IssueNft),
        TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
        TxOutput::Htlc(_, _) => Some(UtxoType::Htlc),
    }
}
pub fn get_utxo_state(output: &TxState) -> UtxoState {
    match output {
        TxState::Confirmed(_, _, _) => UtxoState::Confirmed,
        TxState::Conflicted(_) => UtxoState::Conflicted,
        TxState::InMempool(_) => UtxoState::InMempool,
        TxState::Inactive(_) => UtxoState::Inactive,
        TxState::Abandoned => UtxoState::Abandoned,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UtxoTypes(UtxoTypeInt);

#[derive(Debug, Clone, Copy)]
pub struct UtxoStates(UtxoTypeInt);

pub enum BitFlagError {
    Empty,
}

macro_rules! generate_bitflag_ops {
    ($type_name:ident, $enum_name:ident) => {
        impl $type_name {
            pub const ALL: $type_name = $type_name(UtxoTypeInt::MAX);
            pub const NONE: $type_name = $type_name(UtxoTypeInt::MIN);
        }

        impl std::ops::BitOr<$enum_name> for $type_name {
            type Output = $type_name;

            fn bitor(self, rhs: $enum_name) -> Self::Output {
                Self(self.0 | rhs as UtxoTypeInt)
            }
        }

        impl std::ops::BitOr<$enum_name> for $enum_name {
            type Output = $type_name;

            fn bitor(self, rhs: $enum_name) -> Self::Output {
                $type_name::from(self) | rhs
            }
        }

        impl From<$enum_name> for $type_name {
            fn from(value: $enum_name) -> Self {
                Self(value as UtxoTypeInt)
            }
        }

        impl TryFrom<&Vec<$enum_name>> for $type_name {
            type Error = BitFlagError;

            fn try_from(value: &Vec<$enum_name>) -> Result<Self, BitFlagError> {
                if let Some((first, rest)) = value.split_first() {
                    Ok(rest
                        .iter()
                        .copied()
                        .map(|s| s.into())
                        .fold((*first).into(), |acc, x| acc | x))
                } else {
                    Err(BitFlagError::Empty)
                }
            }
        }

        impl $type_name {
            pub fn contains(&self, value: $enum_name) -> bool {
                (self.0 & value as UtxoTypeInt) != 0
            }
        }
    };
}

generate_bitflag_ops!(UtxoTypes, UtxoType);
generate_bitflag_ops!(UtxoStates, UtxoState);
