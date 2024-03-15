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

pub mod dehexify;
pub mod hexified;
pub mod pubkeyhash;
pub mod rpc;
pub mod traits;

use crate::chain::ChainConfig;
use crate::primitives::{encoding, Bech32Error};
use std::fmt::Display;
use utils::qrcode::{qrcode_from_str, QrCode, QrCodeError};

use self::traits::Addressable;
pub use rpc::RpcAddress;

#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub enum AddressError {
    #[error("Bech32 encoding error: {0}")]
    Bech32EncodingError(Bech32Error),
    #[error("Decoding error: {0}")]
    DecodingError(String),
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

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address<T> {
    address: String,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Address<T> {
    pub fn get(&self) -> &str {
        &self.address
    }
}

impl<T: Addressable> Address<T> {
    pub fn new(cfg: &ChainConfig, object: &T) -> Result<Self, AddressError> {
        Self::new_with_hrp(
            T::address_prefix(object, cfg),
            object.encode_to_bytes_for_address(),
        )
    }

    fn new_with_hrp<D: AsRef<[u8]>>(hrp: &str, data: D) -> Result<Self, AddressError> {
        let d = encoding::encode(hrp, data)?;
        Ok(Self {
            address: d,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn decode_object(&self, cfg: &ChainConfig) -> Result<T, AddressError> {
        let data = encoding::decode(&self.address)?;
        let raw_data = data.data();
        let result = T::decode_from_bytes_from_address(raw_data)
            .map_err(|e| AddressError::DecodingError(e.to_string()))?;
        if data.hrp() != T::address_prefix(&result, cfg) {
            return Err(AddressError::InvalidPrefix(data.hrp().to_owned()));
        }
        Ok(result)
    }

    pub fn from_str(cfg: &ChainConfig, address: &str) -> Result<Self, AddressError> {
        let address = Self {
            address: address.to_owned(),
            _marker: std::marker::PhantomData,
        };
        address.decode_object(cfg)?;
        Ok(address)
    }

    pub fn qrcode(&self) -> Result<impl QrCode + '_, AddressError> {
        let qrcode = qrcode_from_str(&self.address)?;
        Ok(qrcode)
    }

    pub fn to_short_string(&self, cfg: &ChainConfig) -> Result<String, AddressError> {
        use std::str::from_utf8;

        let obj = self.decode_object(cfg)?;
        let prefix_len = obj.address_prefix(cfg).len();

        let result = if self.address.len() < prefix_len + 8 {
            self.to_string()
        } else {
            // prefix + 4 first chars + ... + 4 last chars
            let bytes = self.address.as_bytes();
            format!(
                "{}...{}",
                from_utf8(&bytes[0..prefix_len + 4]).expect("ids are always ascii"),
                from_utf8(&bytes[bytes.len() - 4..bytes.len()]).expect("ids are always ascii"),
            )
        };
        Ok(result)
    }
}

impl<T> Address<T> {
    pub fn into_string(self) -> String {
        self.address
    }
}

impl<T> Display for Address<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.address.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::config::{create_mainnet, create_regtest};
    use crate::chain::{DelegationId, Destination, PoolId};
    use crypto::{
        key::{KeyKind, PrivateKey},
        vrf::VRFPublicKey,
    };
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
        let public_key_hash_dest = Destination::PublicKeyHash(public_key_hash);
        let address = Address::<Destination>::new(&cfg, &public_key_hash_dest)
            .expect("Address from pubkeyhash failed");
        let public_key_hash_restored_dest = address
            .decode_object(&cfg)
            .expect("Failed to extract public key hash from address");
        assert_eq!(public_key_hash_restored_dest, public_key_hash_dest);
    }

    #[test]
    fn to_short_string() {
        let cfg = create_regtest();

        let address =
            Address::<Destination>::from_str(&cfg, "rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68")
                .unwrap();
        assert_eq!("rmt1qyy...eu68", address.to_short_string(&cfg).unwrap());

        let vrf = Address::<VRFPublicKey>::from_str(
            &cfg,
            "rvrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vc2kzme",
        )
        .unwrap();
        assert_eq!("rvrfpk1qre...kzme", vrf.to_short_string(&cfg).unwrap());

        let pool_id = Address::<PoolId>::from_str(
            &cfg,
            "rpool1zg7yccqqjlz38cyghxlxyp5lp36vwecu2g7gudrf58plzjm75tzq99fr6v",
        )
        .unwrap();
        assert_eq!("rpool1zg7...fr6v", pool_id.to_short_string(&cfg).unwrap());

        let delegation_id = Address::<DelegationId>::from_str(
            &cfg,
            "rdelg1zl206x6hkh6cmtmyhmjx3zhtc2qaunckcuvxsywpnervkclj2keq2wmdff",
        )
        .unwrap();
        assert_eq!(
            "rdelg1zl2...mdff",
            delegation_id.to_short_string(&cfg).unwrap()
        );
    }
}
