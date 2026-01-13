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
use crate::primitives::{bech32_encoding, Bech32Error};
use std::fmt::Display;
use utils::{
    ensure,
    qrcode::{qrcode_from_str, QrCode, QrCodeError},
};

use self::traits::Addressable;
pub use rpc::RpcAddress;

#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub enum AddressError {
    #[error("Bech32 encoding error: {0}")]
    Bech32EncodingError(#[from] Bech32Error),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),
    #[error("QR Code error: {0}")]
    QrCodeError(#[from] QrCodeError),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address<T> {
    address: String,
    object: T,
}

impl<T: Addressable> Address<T> {
    pub fn new(cfg: &ChainConfig, object: T) -> Result<Self, AddressError> {
        let hrp = object.address_prefix(cfg);
        let address = bech32_encoding::bech32m_encode(hrp, object.encode_to_bytes_for_address())?;
        Ok(Self { address, object })
    }

    pub fn from_string(
        cfg: &ChainConfig,
        address: impl Into<String>,
    ) -> Result<Self, AddressError> {
        let address = address.into();
        let object = decode_address(cfg, &address)?;

        Ok(Self { address, object })
    }
}

impl<T> Address<T> {
    pub fn as_str(&self) -> &str {
        &self.address
    }

    pub fn into_string(self) -> String {
        self.address
    }

    pub fn as_object(&self) -> &T {
        &self.object
    }

    pub fn into_object(self) -> T {
        self.object
    }

    pub fn qrcode(&self) -> Result<impl QrCode + '_, AddressError> {
        let qrcode = qrcode_from_str(&self.address)?;
        Ok(qrcode)
    }

    pub fn to_short_string(&self) -> String {
        let hrp_len = self.address.find('1').unwrap_or(0);
        let (prefix, rest) = self.address.split_at(hrp_len + 4);

        if rest.len() < 8 {
            self.to_string()
        } else {
            let (_mid, suffix) = rest.split_at(rest.len() - 4);
            format!("{prefix}...{suffix}")
        }
    }
}

impl<T> Display for Address<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.address.fmt(f)
    }
}

pub fn decode_address<T: Addressable>(cfg: &ChainConfig, address: &str) -> Result<T, AddressError> {
    let data = bech32_encoding::bech32m_decode(address)?;
    let object = T::decode_from_bytes_from_address(data.data())
        .map_err(|e| AddressError::DecodingError(e.to_string()))?;

    let hrp_ok = data.hrp() == object.address_prefix(cfg);
    ensure!(hrp_ok, AddressError::InvalidPrefix(data.hrp().to_owned()));

    Ok(object)
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
        let address = Address::<Destination>::new(&cfg, public_key_hash_dest.clone())
            .expect("Address from pubkeyhash failed");
        let public_key_hash_restored_dest = address.into_object();
        assert_eq!(public_key_hash_restored_dest, public_key_hash_dest);
    }

    #[test]
    fn to_short_string() {
        let cfg = create_regtest();

        let address = Address::<Destination>::from_string(
            &cfg,
            "rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68",
        )
        .unwrap();
        assert_eq!("rmt1qyy...eu68", address.to_short_string());

        let vrf = Address::<VRFPublicKey>::from_string(
            &cfg,
            "rvrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vc2kzme",
        )
        .unwrap();
        assert_eq!("rvrfpk1qre...kzme", vrf.to_short_string());

        let pool_id = Address::<PoolId>::from_string(
            &cfg,
            "rpool1zg7yccqqjlz38cyghxlxyp5lp36vwecu2g7gudrf58plzjm75tzq99fr6v",
        )
        .unwrap();
        assert_eq!("rpool1zg7...fr6v", pool_id.to_short_string());

        let delegation_id = Address::<DelegationId>::from_string(
            &cfg,
            "rdelg1zl206x6hkh6cmtmyhmjx3zhtc2qaunckcuvxsywpnervkclj2keq2wmdff",
        )
        .unwrap();
        assert_eq!("rdelg1zl2...mdff", delegation_id.to_short_string());
    }
}
