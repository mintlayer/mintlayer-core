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

use crypto::hash::StreamHasher;
use randomness::{CryptoRng, Rng};
use serialization::{DecodeAll, Encode};
use typename::TypeName;

use crate::{
    address::{hexified::HexifiedAddress, traits::Addressable, AddressError},
    chain::UtxoOutPoint,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Id, H256,
    },
};

use super::ChainConfig;

fn delegation_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    1
}

#[derive(Eq, PartialEq, TypeName)]
pub enum Delegation {}
pub type DelegationId = Id<Delegation>;

impl DelegationId {
    pub fn from_utxo(utxo_outpoint: &UtxoOutPoint) -> Self {
        let mut hasher = DefaultHashAlgoStream::new();

        hash_encoded_to(&utxo_outpoint, &mut hasher);

        // 1 is arbitrary here, we use this as prefix to use this information again
        hash_encoded_to(&delegation_id_preimage_suffix(), &mut hasher);
        Self::new(hasher.finalize().into())
    }

    pub fn random_using<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::new(H256::random_using(rng))
    }

    pub const fn zero() -> Self {
        Self::new(H256::zero())
    }
}

impl Addressable for DelegationId {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.delegation_id_address_prefix()
    }

    fn encode_to_bytes_for_address(&self) -> Vec<u8> {
        self.encode()
    }

    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(address_bytes: T) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::decode_all(&mut address_bytes.as_ref())
            .map_err(|e| AddressError::DecodingError(e.to_string()))
    }
    fn json_wrapper_prefix() -> &'static str {
        "HexifiedDelegationId"
    }
}

impl serde::Serialize for DelegationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexifiedAddress::serde_serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DelegationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HexifiedAddress::<Self>::serde_deserialize(deserializer)
    }
}
