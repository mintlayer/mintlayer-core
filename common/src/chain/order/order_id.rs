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
    address::{hexified::HexifiedAddress, traits::Addressable, AddressError},
    chain::{ChainConfig, UtxoOutPoint},
    primitives::{id::hash_encoded, Id, H256},
};
use randomness::{CryptoRng, Rng};
use serialization::{DecodeAll, Encode};
use typename::TypeName;

#[derive(Eq, PartialEq, TypeName)]
pub enum Order {}
pub type OrderId = Id<Order>;

impl OrderId {
    pub fn from_utxo(utxo_outpoint: &UtxoOutPoint) -> Self {
        Self::new(hash_encoded(utxo_outpoint))
    }

    pub fn random_using<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::new(H256::random_using(rng))
    }

    pub const fn zero() -> Self {
        Self::new(H256::zero())
    }
}

impl Addressable for OrderId {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.order_id_address_prefix()
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
        "HexifiedOrderId"
    }
}

impl serde::Serialize for OrderId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexifiedAddress::serde_serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for OrderId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HexifiedAddress::<Self>::serde_deserialize(deserializer)
    }
}
