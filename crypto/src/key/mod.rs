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

pub mod rschnorr;
pub mod signature;

use serialization::{Decode, Encode};

use crate::key::Signature::{RistrettoSchnorr, RistrettoSchnorr2};
use crate::random::make_true_rng;
pub use signature::Signature;

use self::rschnorr::RistrettoSignatureError;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum SignatureError {
    Unknown,
    DataConversionError(String),
    SignatureConstructionError,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum KeyKind {
    RistrettoSchnorr,
    RistrettoSchnorr2,
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
    RistrettoSchnorr(rschnorr::MLRistrettoPrivateKey),
    RistrettoSchnorr2(rschnorr::ML2RistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum PublicKeyHolder {
    RistrettoSchnorr(rschnorr::MLRistrettoPublicKey),
    RistrettoSchnorr2(rschnorr::ML2RistrettoPublicKey),
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
                let k = rschnorr::MLRistrettoPrivateKey::new(&mut rng);
                (
                    PrivateKey {
                        key: PrivateKeyHolder::RistrettoSchnorr(k.0),
                    },
                    crate::key::PublicKey {
                        pub_key: PublicKeyHolder::RistrettoSchnorr(k.1),
                    },
                )
            }
            KeyKind::RistrettoSchnorr2 => {
                let k = rschnorr::ML2RistrettoPrivateKey::new(&mut rng);
                (
                    PrivateKey {
                        key: PrivateKeyHolder::RistrettoSchnorr2(k.0),
                    },
                    PublicKey {
                        pub_key: PublicKeyHolder::RistrettoSchnorr2(k.1),
                    },
                )
            }
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.key {
            PrivateKeyHolder::RistrettoSchnorr(_) => KeyKind::RistrettoSchnorr,
            PrivateKeyHolder::RistrettoSchnorr2(_) => KeyKind::RistrettoSchnorr2,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &PrivateKeyHolder {
        &self.key
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        let signature = match &self.key {
            PrivateKeyHolder::RistrettoSchnorr(ref k) => {
                let mut rng = make_true_rng();
                RistrettoSchnorr(k.sign_message(&mut rng, msg)?)
            }
            PrivateKeyHolder::RistrettoSchnorr2(ref k) => RistrettoSchnorr2(k.sign_message(msg)?),
        };
        Ok(signature)
    }
}

impl PublicKey {
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        match private_key.get_internal_key() {
            PrivateKeyHolder::RistrettoSchnorr(ref k) => crate::key::PublicKey {
                pub_key: PublicKeyHolder::RistrettoSchnorr(
                    rschnorr::MLRistrettoPublicKey::from_private_key(k),
                ),
            },
            PrivateKeyHolder::RistrettoSchnorr2(ref k) => PublicKey {
                pub_key: PublicKeyHolder::RistrettoSchnorr2(
                    rschnorr::ML2RistrettoPublicKey::from_private_key(k),
                ),
            },
        }
    }

    pub fn verify_message(&self, signature: &Signature, msg: &[u8]) -> bool {
        match &self.pub_key {
            PublicKeyHolder::RistrettoSchnorr(ref k) => match signature {
                RistrettoSchnorr(s) => k.verify_message(s, msg),
                _ => panic!("Wrong key/signature combination"),
            },
            PublicKeyHolder::RistrettoSchnorr2(ref k) => match signature {
                RistrettoSchnorr2(s) => k.verify_message(s, msg),
                _ => panic!("Wrong key/signature combination"),
            },
        }
    }

    pub fn is_aggregable(&self) -> bool {
        match self.pub_key {
            PublicKeyHolder::RistrettoSchnorr(_) => true,
            PublicKeyHolder::RistrettoSchnorr2(_) => true,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
    fn sign_and_verify2() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr2);
        assert_eq!(sk.kind(), KeyKind::RistrettoSchnorr2);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }
}
