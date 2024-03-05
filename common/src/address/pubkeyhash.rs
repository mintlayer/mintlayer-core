// Copyright (c) 2022 RBB S.r.l
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

// TODO: consider removing this in the future when fixed-hash fixes this problem
#![allow(clippy::non_canonical_clone_impl)]

use crypto::key::PublicKey;
use generic_array::sequence::Split;
use serialization::{Decode, Encode};

use crate::address::AddressError;
use crate::{chain::classic_multisig::ClassicMultisigChallenge, primitives::id::DefaultHashAlgo};

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum PublicKeyHashError {
    #[error("Conversion from a data array to public key hash failed; probably invalid length")]
    ConversionFromDataFailed,
    #[error("Conversion from an address to public key hash failed: {0}")]
    ConversionFromAddressFailed(#[from] AddressError),
}

const HASH_SIZE: usize = 20;

fixed_hash::construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct PublicKeyHash(HASH_SIZE);
}

impl From<&PublicKey> for PublicKeyHash {
    fn from(pk: &PublicKey) -> Self {
        let hash = crypto::hash::hash::<DefaultHashAlgo, _>(pk.encode()).split().0.into();
        Self(hash)
    }
}

impl From<&ClassicMultisigChallenge> for PublicKeyHash {
    fn from(challenge: &ClassicMultisigChallenge) -> Self {
        let hash = crypto::hash::hash::<DefaultHashAlgo, _>(challenge.encode()).split().0.into();
        Self(hash)
    }
}

impl TryFrom<Vec<u8>> for PublicKeyHash {
    type Error = PublicKeyHashError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != HASH_SIZE {
            return Err(PublicKeyHashError::ConversionFromDataFailed);
        }
        let array: [u8; HASH_SIZE] =
            v.try_into().map_err(|_| PublicKeyHashError::ConversionFromDataFailed)?;
        Ok(Self(array))
    }
}

impl rpc_description::HasValueHint for PublicKeyHash {
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::HEX_STRING;
}
