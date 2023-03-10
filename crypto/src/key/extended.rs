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

use serialization::{Decode, Encode};

use crate::key::hdkd::child_number::ChildNumber;
use crate::key::hdkd::derivable::{Derivable, DerivationError};
use crate::key::hdkd::derivation_path::DerivationPath;
use crate::key::key_holder::{ExtendedPrivateKeyHolder, ExtendedPublicKeyHolder};
use crate::key::secp256k1::extended_keys::{
    Secp256k1ExtendedPrivateKey, Secp256k1ExtendedPublicKey,
};
use crate::key::{PrivateKey, PublicKey};
use crate::random::make_true_rng;
use crate::random::{CryptoRng, Rng};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum ExtendedKeyKind {
    #[codec(index = 0)]
    Secp256k1Schnorr,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct ExtendedPrivateKey {
    key: ExtendedPrivateKeyHolder,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct ExtendedPublicKey {
    pub_key: ExtendedPublicKeyHolder,
}

impl ExtendedPrivateKey {
    pub fn new_master(
        seed: &[u8],
        key_kind: ExtendedKeyKind,
    ) -> Result<ExtendedPrivateKey, DerivationError> {
        match key_kind {
            ExtendedKeyKind::Secp256k1Schnorr => {
                let secp_key = Secp256k1ExtendedPrivateKey::new_master(seed)?;
                Ok(ExtendedPrivateKey {
                    key: ExtendedPrivateKeyHolder::Secp256k1Schnorr(secp_key),
                })
            }
        }
    }

    pub fn new_from_entropy(key_kind: ExtendedKeyKind) -> (ExtendedPrivateKey, ExtendedPublicKey) {
        Self::new_from_rng(&mut make_true_rng(), key_kind)
    }

    pub fn new_from_rng(
        rng: &mut (impl Rng + CryptoRng),
        key_kind: ExtendedKeyKind,
    ) -> (ExtendedPrivateKey, ExtendedPublicKey) {
        match key_kind {
            ExtendedKeyKind::Secp256k1Schnorr => {
                let k = Secp256k1ExtendedPrivateKey::new(rng);
                (
                    ExtendedPrivateKey {
                        key: ExtendedPrivateKeyHolder::Secp256k1Schnorr(k.0),
                    },
                    ExtendedPublicKey {
                        pub_key: ExtendedPublicKeyHolder::Secp256k1Schnorr(k.1),
                    },
                )
            }
        }
    }

    pub fn kind(&self) -> ExtendedKeyKind {
        match self.key {
            ExtendedPrivateKeyHolder::Secp256k1Schnorr(_) => ExtendedKeyKind::Secp256k1Schnorr,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &ExtendedPrivateKeyHolder {
        &self.key
    }

    pub fn private_key(self) -> PrivateKey {
        match self.key {
            ExtendedPrivateKeyHolder::Secp256k1Schnorr(k) => k.private_key.into(),
        }
    }

    pub fn to_public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey::from_private_key(self)
    }
}

impl ExtendedPublicKey {
    pub fn kind(&self) -> ExtendedKeyKind {
        match self.pub_key {
            ExtendedPublicKeyHolder::Secp256k1Schnorr(_) => ExtendedKeyKind::Secp256k1Schnorr,
        }
    }

    pub fn get_internal_key(&self) -> &ExtendedPublicKeyHolder {
        &self.pub_key
    }

    pub fn from_private_key(private_key: &ExtendedPrivateKey) -> ExtendedPublicKey {
        match private_key.get_internal_key() {
            ExtendedPrivateKeyHolder::Secp256k1Schnorr(ref k) => {
                let secp_key = Secp256k1ExtendedPublicKey::from_private_key(k);
                ExtendedPublicKey {
                    pub_key: ExtendedPublicKeyHolder::Secp256k1Schnorr(secp_key),
                }
            }
        }
    }

    pub fn into_public_key(self) -> PublicKey {
        match self.pub_key {
            ExtendedPublicKeyHolder::Secp256k1Schnorr(k) => k.public_key.into(),
        }
    }
}

impl Derivable for ExtendedPrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.key {
            ExtendedPrivateKeyHolder::Secp256k1Schnorr(key) => {
                let secp_key = key.derive_child(num)?;
                Ok(ExtendedPrivateKey {
                    key: ExtendedPrivateKeyHolder::Secp256k1Schnorr(secp_key),
                })
            }
        }
    }

    fn get_derivation_path(&self) -> DerivationPath {
        match self.key {
            ExtendedPrivateKeyHolder::Secp256k1Schnorr(ref key) => key.get_derivation_path(),
        }
    }
}

impl Derivable for ExtendedPublicKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.pub_key {
            ExtendedPublicKeyHolder::Secp256k1Schnorr(pub_key) => {
                let child_pub_key = pub_key.derive_child(num)?;
                Ok(ExtendedPublicKey {
                    pub_key: ExtendedPublicKeyHolder::Secp256k1Schnorr(child_pub_key),
                })
            }
        }
    }

    fn get_derivation_path(&self) -> DerivationPath {
        match self.pub_key {
            ExtendedPublicKeyHolder::Secp256k1Schnorr(ref pub_key) => pub_key.get_derivation_path(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::hdkd::derivation_path::DerivationPath;
    use bip39::Mnemonic;
    use hex::ToHex;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::random::make_seedable_rng;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_and_verify_extended_secp256k1schnorr(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, pk) =
            ExtendedPrivateKey::new_from_rng(&mut rng, ExtendedKeyKind::Secp256k1Schnorr);
        assert_eq!(sk.kind(), ExtendedKeyKind::Secp256k1Schnorr);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.private_key().sign_message(&msg).unwrap();
        assert!(pk.into_public_key().verify_message(&sig, &msg));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn derive_secp256k1schnorr(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, _) = ExtendedPrivateKey::new_from_rng(&mut rng, ExtendedKeyKind::Secp256k1Schnorr);
        let sk1 = sk
            .clone()
            .derive_child(ChildNumber::from_hardened(1.try_into().unwrap()))
            .unwrap();
        let sk2 = sk1.derive_child(ChildNumber::from_hardened(2.try_into().unwrap())).unwrap();
        let sk3 = sk2.derive_child(ChildNumber::from_hardened(3.try_into().unwrap())).unwrap();
        let sk3_alt = sk.derive_path(&DerivationPath::from_str("m/1h/2h/3h").unwrap()).unwrap();
        assert_eq!(sk3, sk3_alt);
        let sk4 = sk3.derive_child(ChildNumber::from_normal(4.try_into().unwrap())).unwrap();
        let sk4_alt =
            sk3_alt.derive_path(&DerivationPath::from_str("m/1h/2h/3h/4").unwrap()).unwrap();
        assert_eq!(sk4, sk4_alt);
    }

    #[test]
    fn master_key_from_mnemonic_secp256k1schnorr() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str).unwrap();
        let master_key = ExtendedPrivateKey::new_master(
            &mnemonic.to_seed_normalized(""),
            ExtendedKeyKind::Secp256k1Schnorr,
        )
        .unwrap();
        let master_pub_key = ExtendedPublicKey::from_private_key(&master_key);
        assert_eq!(
            master_key.encode().encode_hex::<String>(),
            "00007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
        );
        assert_eq!(
            master_pub_key.encode().encode_hex::<String>(),
            "00007923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494"
        );
    }
}
