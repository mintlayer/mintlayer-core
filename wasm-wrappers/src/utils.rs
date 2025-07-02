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

use std::str::FromStr as _;

use common::{
    address::{traits::Addressable, Address},
    chain::{
        signature::{
            inputsig::{
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                InputWitness, InputWitnessTag,
            },
            sighash::sighashtype::SigHashType,
        },
        ChainConfig,
    },
    primitives,
};
use serialization::Decode;

use crate::error::Error;

pub fn decode_raw_array<T: Decode>(mut array: &[u8]) -> Result<Vec<T>, serialization::Error> {
    let mut result = Vec::new();

    while !array.is_empty() {
        let item = T::decode(&mut array)?;
        result.push(item);
    }

    Ok(result)
}

pub fn parse_addressable<T: Addressable>(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<T, Error> {
    let addressable = Address::from_string(chain_config, address)
        .map_err(|error| Error::AddressableParseError {
            addressable: address.to_owned(),
            error,
        })?
        .into_object();
    Ok(addressable)
}

pub fn internal_amount_from_atoms_str(atoms: &str) -> Result<primitives::Amount, Error> {
    primitives::amount::UnsignedIntType::from_str(atoms)
        .ok()
        .map(primitives::Amount::from_atoms)
        .ok_or_else(|| Error::AtomsAmountParseError {
            atoms: atoms.to_owned(),
        })
}

pub fn extract_htlc_spend(
    witness: &InputWitness,
) -> Result<(AuthorizedHashedTimelockContractSpend, SigHashType), Error> {
    match witness {
        InputWitness::NoSignature(_) => {
            Err(Error::UnexpectedWitnessType(InputWitnessTag::NoSignature))
        }
        InputWitness::Standard(sig) => Ok((
            AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())
                .map_err(Error::HtlcSpendDecodingError)?,
            sig.sighash_type(),
        )),
    }
}
