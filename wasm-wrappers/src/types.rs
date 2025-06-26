// Copyright (c) 2021-2025 RBB S.r.l
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

use wasm_bindgen::prelude::*;

use common::{
    chain::{
        config::ChainType,
        signature::sighash::sighashtype::SigHashType,
        tokens::{IsTokenFreezable, IsTokenUnfreezable},
    },
    primitives::{self},
};

use crate::{error::Error, utils::internal_amount_from_atoms_str};

/// Amount type abstraction. The amount type is stored in a string
/// since JavaScript number type cannot fit 128-bit integers.
/// The amount is given as an integer in units of "atoms".
/// Atoms are the smallest, indivisible amount of a coin or token.
#[wasm_bindgen]
pub struct Amount {
    atoms: String,
}

#[wasm_bindgen]
impl Amount {
    #[wasm_bindgen]
    pub fn from_atoms(atoms: String) -> Self {
        Self { atoms }
    }

    #[wasm_bindgen]
    pub fn atoms(self) -> String {
        self.atoms
    }
}

impl Amount {
    pub fn as_internal_amount(&self) -> Result<primitives::Amount, Error> {
        internal_amount_from_atoms_str(&self.atoms)
    }

    pub fn from_internal_amount(amount: primitives::Amount) -> Self {
        Self {
            atoms: amount.into_atoms().to_string(),
        }
    }
}

/// The network, for which an operation to be done. Mainnet, testnet, etc.
#[wasm_bindgen]
#[derive(Debug, Copy, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

/// Indicates whether a token can be frozen
#[wasm_bindgen]
pub enum FreezableToken {
    No,
    Yes,
}

impl From<FreezableToken> for IsTokenFreezable {
    fn from(value: FreezableToken) -> Self {
        match value {
            FreezableToken::No => IsTokenFreezable::No,
            FreezableToken::Yes => IsTokenFreezable::Yes,
        }
    }
}

/// Indicates whether a token can be unfrozen once frozen
#[wasm_bindgen]
pub enum TokenUnfreezable {
    No,
    Yes,
}

impl From<TokenUnfreezable> for IsTokenUnfreezable {
    fn from(value: TokenUnfreezable) -> Self {
        match value {
            TokenUnfreezable::No => IsTokenUnfreezable::No,
            TokenUnfreezable::Yes => IsTokenUnfreezable::Yes,
        }
    }
}

/// The token supply of a specific token, set on issuance
#[wasm_bindgen]
pub enum TotalSupply {
    /// Can be issued with no limit, but then can be locked to have a fixed supply.
    Lockable,
    /// Unlimited supply, no limits except for numeric limits due to u128
    Unlimited,
    /// On issuance, the total number of coins is fixed
    Fixed,
}

/// A utxo can either come from a transaction or a block reward. This enum signifies that.
#[wasm_bindgen]
pub enum SourceId {
    Transaction,
    BlockReward,
}

/// The part of the transaction that will be committed in the signature. Similar to bitcoin's sighash.
#[allow(clippy::upper_case_acronyms)]
#[wasm_bindgen]
pub enum SignatureHashType {
    ALL,
    NONE,
    SINGLE,
    ANYONECANPAY,
}

impl From<SignatureHashType> for SigHashType {
    fn from(value: SignatureHashType) -> Self {
        let value = match value {
            SignatureHashType::ALL => SigHashType::ALL,
            SignatureHashType::SINGLE => SigHashType::SINGLE,
            SignatureHashType::ANYONECANPAY => SigHashType::ANYONECANPAY,
            SignatureHashType::NONE => SigHashType::NONE,
        };

        SigHashType::try_from(value).expect("should not fail")
    }
}
