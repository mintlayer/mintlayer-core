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
pub mod secp256k1;
pub mod signature;

use serialization::{Decode, Encode};

use crate::key::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::key::Signature::Secp256k1Schnorr;
use crate::random::make_true_rng;
use crate::random::{CryptoRng, Rng};
pub use signature::Signature;

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
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct PrivateKey {
    key: PrivateKeyHolder,
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Decode, Encode)]
pub struct PublicKey {
    pub_key: PublicKeyHolder,
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
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.key {
            PrivateKeyHolder::Secp256k1Schnorr(_) => KeyKind::Secp256k1Schnorr,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &PrivateKeyHolder {
        &self.key
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        let signature = match &self.key {
            PrivateKeyHolder::Secp256k1Schnorr(ref k) => Secp256k1Schnorr(k.sign_message(msg)),
        };
        Ok(signature)
    }
}

impl From<Secp256k1PrivateKey> for PrivateKey {
    fn from(sk: Secp256k1PrivateKey) -> Self {
        Self {
            key: PrivateKeyHolder::Secp256k1Schnorr(sk),
        }
    }
}

impl PublicKey {
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        match private_key.get_internal_key() {
            PrivateKeyHolder::Secp256k1Schnorr(ref k) => {
                Secp256k1PublicKey::from_private_key(k).into()
            }
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(_) => KeyKind::Secp256k1Schnorr,
        }
    }

    pub fn verify_message(&self, signature: &Signature, msg: &[u8]) -> bool {
        match &self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(ref k) => match signature {
                Secp256k1Schnorr(s) => k.verify_message(s, msg),
            },
        }
    }

    pub fn is_aggregable(&self) -> bool {
        match self.pub_key {
            PublicKeyHolder::Secp256k1Schnorr(_) => false,
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
    use rstest::rstest;
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
}
