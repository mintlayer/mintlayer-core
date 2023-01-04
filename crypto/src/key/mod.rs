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

pub mod extended;
pub mod hdkd;
mod key_holder;
pub mod rschnorr;
pub mod secp256k1;
pub mod signature;

use serialization::{Decode, Encode};

use crate::key::rschnorr::{MLRistrettoPrivateKey, MLRistrettoPublicKey, RistrettoSignatureError};
use crate::key::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::key::Signature::{RistrettoSchnorr, Secp256k1Schnorr};
use crate::random::make_true_rng;
use crate::random::{CryptoRng, Rng};
pub use signature::Signature;

use self::hdkd::child_number::ChildNumber;
use self::hdkd::derivable::{Derivable, DerivationError};
use self::key_holder::{PrivateKeyHolder, PublicKeyHolder};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum SignatureError {
    Unknown,
    DataConversionError(String),
    SignatureConstructionError,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum KeyKind {
    #[codec(index = 0)]
    Secp256k1Schnorr,
    #[codec(index = 1)]
    RistrettoSchnorr,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct PrivateKey {
    key: PrivateKeyHolder,
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Decode, Encode)]
pub struct PublicKey {
    pub_key: PublicKeyHolder,
}

impl From<RistrettoSignatureError> for SignatureError {
    fn from(e: RistrettoSignatureError) -> Self {
        match e {
            RistrettoSignatureError::ByteConversionError(s) => {
                SignatureError::DataConversionError(s)
            }
        }
    }
}

impl PrivateKey {
    pub fn new_from_entropy(key_kind: KeyKind) -> (PrivateKey, PublicKey) {
        Self::new_from_rng(&mut make_true_rng(), key_kind)
    }

    pub fn new_from_rng(
        rng: &mut (impl Rng + CryptoRng),
        key_kind: KeyKind,
    ) -> (PrivateKey, PublicKey) {
        match key_kind {
            KeyKind::Secp256k1Schnorr => {
                let k = Secp256k1PrivateKey::new(rng);
                (k.0.into(), k.1.into())
            }
            KeyKind::RistrettoSchnorr => {
                let k = MLRistrettoPrivateKey::new(rng);
                (
                    PrivateKey {
                        key: PrivateKeyHolder::RistrettoSchnorr(k.0),
                    },
                    PublicKey {
                        pub_key: PublicKeyHolder::RistrettoSchnorr(k.1),
                    },
                )
            }
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.key {
            PrivateKeyHolder::Secp256k1Schnorr(_) => KeyKind::Secp256k1Schnorr,
            PrivateKeyHolder::RistrettoSchnorr(_) => KeyKind::RistrettoSchnorr,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &PrivateKeyHolder {
        &self.key
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        let signature = match &self.key {
            PrivateKeyHolder::Secp256k1Schnorr(ref k) => Secp256k1Schnorr(k.sign_message(msg)),
            PrivateKeyHolder::RistrettoSchnorr(ref k) => RistrettoSchnorr(k.sign_message(msg)?),
        };
        Ok(signature)
    }
}

impl Derivable for PrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.key {
            PrivateKeyHolder::Secp256k1Schnorr(_) => Err(DerivationError::UnsupportedKeyType),
            PrivateKeyHolder::RistrettoSchnorr(key) => Ok(key.derive_child(num)?.into()),
        }
    }
}

impl From<Secp256k1PrivateKey> for PrivateKey {
    fn from(sk: Secp256k1PrivateKey) -> Self {
        Self {
            key: PrivateKeyHolder::Secp256k1Schnorr(sk),
        }
    }
}

impl From<MLRistrettoPrivateKey> for PrivateKey {
    fn from(key: MLRistrettoPrivateKey) -> Self {
        PrivateKey {
            key: PrivateKeyHolder::RistrettoSchnorr(key),
        }
    }
}

impl PublicKey {
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        match private_key.get_internal_key() {
            PrivateKeyHolder::Secp256k1Schnorr(ref k) => {
                Secp256k1PublicKey::from_private_key(k).into()
            }
            PrivateKeyHolder::RistrettoSchnorr(ref k) => PublicKey {
                pub_key: PublicKeyHolder::RistrettoSchnorr(MLRistrettoPublicKey::from_private_key(
                    k,
                )),
            },
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(_) => KeyKind::Secp256k1Schnorr,
            PublicKeyHolder::RistrettoSchnorr(_) => KeyKind::RistrettoSchnorr,
        }
    }

    pub fn verify_message(&self, signature: &Signature, msg: &[u8]) -> bool {
        match &self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(ref k) => match signature {
                Secp256k1Schnorr(s) => k.verify_message(s, msg),
                _ => panic!("Wrong key/signature combination"),
            },
            PublicKeyHolder::RistrettoSchnorr(ref k) => match signature {
                RistrettoSchnorr(s) => k.verify_message(s, msg),
                _ => panic!("Wrong key/signature combination"),
            },
        }
    }

    pub fn is_aggregable(&self) -> bool {
        match self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(_) => false,
            PublicKeyHolder::RistrettoSchnorr(_) => true,
        }
    }
}

impl From<Secp256k1PublicKey> for PublicKey {
    fn from(pk: Secp256k1PublicKey) -> Self {
        Self {
            pub_key: PublicKeyHolder::Secp256k1Schnorr(pk),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::hdkd::derivation_path::DerivationPath;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::random::make_seedable_rng;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_and_verify_secp256k1schnorr(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        assert_eq!(sk.kind(), KeyKind::Secp256k1Schnorr);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_and_verify_ristretto(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        assert_eq!(sk.kind(), KeyKind::RistrettoSchnorr);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn derive_ristretto(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let sk1 = sk
            .clone()
            .derive_child(ChildNumber::from_hardened(123.try_into().unwrap()))
            .unwrap();
        let sk2 = sk1.derive_child(ChildNumber::from_hardened(456.try_into().unwrap())).unwrap();
        let sk3 = sk2.derive_child(ChildNumber::from_hardened(789.try_into().unwrap())).unwrap();
        let sk4 = sk.derive_path(&DerivationPath::from_str("m/123h/456h/789h").unwrap()).unwrap();
        assert_eq!(sk3, sk4);
    }
}
