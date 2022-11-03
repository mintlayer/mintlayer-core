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

pub mod hdkd;
pub mod rschnorr;
pub mod signature;

use serialization::{Decode, Encode};

use crate::key::hdkd::derivation_path::ChildNumber;
use crate::key::rschnorr::{MLRistrettoPrivateKey, MLRistrettoPublicKey, RistrettoSignatureError};
use crate::key::Signature::RistrettoSchnorr;
use crate::random::make_true_rng;
pub use signature::Signature;

use self::hdkd::derivable::{Derivable, DerivationError};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum SignatureError {
    Unknown,
    DataConversionError(String),
    SignatureConstructionError,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum KeyKind {
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

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub(crate) enum PrivateKeyHolder {
    RistrettoSchnorr(MLRistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum PublicKeyHolder {
    RistrettoSchnorr(MLRistrettoPublicKey),
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
    pub fn new(key_kind: KeyKind) -> (PrivateKey, PublicKey) {
        let mut rng = make_true_rng();
        match key_kind {
            KeyKind::RistrettoSchnorr => {
                let k = MLRistrettoPrivateKey::new(&mut rng);
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
            PrivateKeyHolder::RistrettoSchnorr(_) => KeyKind::RistrettoSchnorr,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &PrivateKeyHolder {
        &self.key
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        let signature = match &self.key {
            PrivateKeyHolder::RistrettoSchnorr(ref k) => RistrettoSchnorr(k.sign_message(msg)?),
        };
        Ok(signature)
    }
}

impl Derivable for PrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.key {
            PrivateKeyHolder::RistrettoSchnorr(key) => Ok(key.derive_child(num)?.into()),
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
            PrivateKeyHolder::RistrettoSchnorr(ref k) => PublicKey {
                pub_key: PublicKeyHolder::RistrettoSchnorr(MLRistrettoPublicKey::from_private_key(
                    k,
                )),
            },
        }
    }

    pub fn verify_message(&self, signature: &Signature, msg: &[u8]) -> bool {
        let PublicKeyHolder::RistrettoSchnorr(k) = &self.pub_key;
        match signature {
            RistrettoSchnorr(s) => k.verify_message(s, msg),
        }
    }

    pub fn is_aggregable(&self) -> bool {
        match self.pub_key {
            PublicKeyHolder::RistrettoSchnorr(_) => true,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::hdkd::derivation_path::DerivationPath;
    use std::str::FromStr;

    #[test]
    fn sign_and_verify() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        assert_eq!(sk.kind(), KeyKind::RistrettoSchnorr);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn derive() {
        let (sk, _) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let sk1 = sk.clone().derive_child(ChildNumber::hardened(123).unwrap()).unwrap();
        let sk2 = sk1.derive_child(ChildNumber::hardened(456).unwrap()).unwrap();
        let sk3 = sk2.derive_child(ChildNumber::hardened(789).unwrap()).unwrap();
        let sk4 = sk.derive_path(&DerivationPath::from_str("m/123h/456h/789h").unwrap()).unwrap();
        assert_eq!(sk3, sk4);
    }
}
