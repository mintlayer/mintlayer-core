// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod rschnorr;
pub mod signature;

use serialization::{Decode, Encode};

use crate::random::make_true_rng;
pub use signature::Signature;

use self::rschnorr::RistrittoSignatureError;

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
    RistrettoSchnorr(rschnorr::MLRistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum PublicKeyHolder {
    RistrettoSchnorr(rschnorr::MLRistrettoPublicKey),
}

impl From<RistrittoSignatureError> for SignatureError {
    fn from(e: RistrittoSignatureError) -> Self {
        match e {
            RistrittoSignatureError::ByteConversionError(s) => {
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
        let mut rng = make_true_rng();
        let PrivateKeyHolder::RistrettoSchnorr(k) = &self.key;
        let sig = k.sign_message(&mut rng, msg)?;
        Ok(Signature::RistrettoSchnorr(sig))
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
        }
    }

    pub fn verify_message(&self, signature: &Signature, msg: &[u8]) -> bool {
        use crate::key::Signature::RistrettoSchnorr;

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

    #[test]
    fn sign_and_verify() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        assert_eq!(sk.kind(), KeyKind::RistrettoSchnorr);
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }
}
