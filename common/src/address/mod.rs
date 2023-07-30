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

use std::fmt::Display;

use crate::chain::{ChainConfig, Destination};
use crate::primitives::{encoding, Bech32Error, DecodedArbitraryDataFromBech32};
pub mod pubkeyhash;
use serialization::{Decode, DecodeAll, Encode, Input};
use utils::qrcode::{qrcode_from_str, QrCode, QrCodeError};

pub trait AddressableData<T: AsRef<[u8]>> {
    fn encode(&self) -> Result<String, Bech32Error> {
        encoding::encode(self.hrp(), self.data())
    }

    fn decode(&mut self, addr: &str) -> Result<DecodedArbitraryDataFromBech32, Bech32Error> {
        encoding::decode(addr)
    }

    fn hrp(&self) -> &str;
    fn set_hrp(&mut self, hrp: String);

    fn data(&self) -> T;
    fn set_data(&mut self, data: &[u8]);
}

#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub enum AddressError {
    #[error("Bech32 encoding error: {0}")]
    Bech32EncodingError(Bech32Error),
    #[error("Destination decoding error: {0}")]
    DestinationDecodingError(String),
    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),
    #[error("QR Code error: {0}")]
    QrCodeError(#[from] QrCodeError),
}

impl From<Bech32Error> for AddressError {
    fn from(err: Bech32Error) -> Self {
        AddressError::Bech32EncodingError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    address: String,
}

impl Address {
    pub fn new_from_destination(
        cfg: &ChainConfig,
        destination: &Destination,
    ) -> Result<Self, AddressError> {
        Self::new_with_hrp(cfg.address_prefix(destination), destination.encode())
    }

    pub(crate) fn new_with_hrp<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<Self, AddressError> {
        let d = encoding::encode(hrp, data)?;
        Ok(Self { address: d })
    }

    pub fn destination(&self, cfg: &ChainConfig) -> Result<Destination, AddressError> {
        let data = encoding::decode(&self.address)?;
        let raw_dest = data.data();
        let destination = Destination::decode_all(&mut &raw_dest[..])
            .map_err(|e| AddressError::DestinationDecodingError(e.to_string()))?;
        if data.hrp() != cfg.address_prefix(&destination) {
            return Err(AddressError::InvalidPrefix(data.hrp().to_owned()));
        }
        Ok(destination)
    }

    fn destination_internal(&self) -> Result<Vec<u8>, AddressError> {
        let data = encoding::decode(&self.address)?;
        Ok(data.data().to_owned())
    }

    pub fn from_str(cfg: &ChainConfig, address: &str) -> Result<Self, AddressError> {
        let address = Self {
            address: address.to_owned(),
        };
        address.destination(cfg)?;
        Ok(address)
    }

    pub fn get(&self) -> &str {
        &self.address
    }

    pub fn qrcode(&self) -> Result<impl QrCode + '_, AddressError> {
        let qrcode = qrcode_from_str(&self.address)?;
        Ok(qrcode)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.address.fmt(f)
    }
}

impl Decode for Address {
    fn decode<I: Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let address = String::decode(input)?;
        let result = Self { address };
        result.destination_internal().map_err(|_| {
            serialization::Error::from("Address decoding failed")
                .chain(format!("with given address {}", result.address))
        })?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::config::create_mainnet;
    use crypto::key::{KeyKind, PrivateKey};
    use pubkeyhash::PublicKeyHash;
    use rstest::rstest;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let cfg = create_mainnet();
        let (_priv_key, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let public_key_hash = PublicKeyHash::from(&pub_key);
        let public_key_hash_dest = Destination::Address(public_key_hash);
        let address = Address::new_from_destination(&cfg, &public_key_hash_dest)
            .expect("Address from pubkeyhash failed");
        let public_key_hash_restored_dest = address
            .destination(&cfg)
            .expect("Failed to extract public key hash from address");
        assert_eq!(public_key_hash_restored_dest, public_key_hash_dest);
    }
}
