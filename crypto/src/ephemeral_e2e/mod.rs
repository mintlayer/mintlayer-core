// Copyright (c) 2023 RBB S.r.l
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

pub mod error;

use serialization::DecodeAll;
use serialization::{Decode, Encode};
use zeroize::Zeroize;

use crate::symkey;
use randomness::{CryptoRng, Rng};

use self::error::Error;

const PUBLIC_KEY_SIZE: usize = 32;

/// Short-term end-to-end encryption key. This encryption scheme IS NOT MEANT to be long term, as byte stability is not guaranteed.
///
/// DO NOT attempt to make this a long-term encryption scheme, by, e.g., storing the key in a database.
/// The secret key is not guaranteed to be stable across versions of this library. Hence,
/// no serialization/deserialization is provided.
///
/// To encrypt data end-to-end:
///
/// 1. Generate a new keypair with `EndToEndPrivateKey::new_from_rng()` at both ends/parties
/// 2. Share the public keys
/// 3. Compute the shared secret with `EndToEndPrivateKey::shared_secret()`
/// 4. Encrypt the data with `SharedSecret::encrypt()`
/// 5. Send the encrypted data to the other end
/// 6. Decrypt the data with `SharedSecret::decrypt()`
#[derive(Zeroize)]
pub struct EndToEndPrivateKey {
    key: x25519_dalek::ReusableSecret,
}

impl EndToEndPrivateKey {
    pub fn new_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> EndToEndPrivateKey {
        EndToEndPrivateKey {
            key: x25519_dalek::ReusableSecret::random_from_rng(rng),
        }
    }

    pub fn public_key(&self) -> EndToEndPublicKey {
        EndToEndPublicKey {
            key: x25519_dalek::PublicKey::from(&self.key),
        }
    }

    pub fn shared_secret(&self, other_public_key: &EndToEndPublicKey) -> SharedSecret {
        assert!(
            self.public_key() != *other_public_key,
            "You can't share a secret with yourself. If you don't understand the implications, then please let someone else do this. You're not ready."
        );

        SharedSecret {
            secret: self.key.diffie_hellman(&other_public_key.key).to_bytes(),
        }
    }
}

#[derive(Zeroize, Clone, PartialEq, Eq, Debug)]
pub struct EndToEndPublicKey {
    key: x25519_dalek::PublicKey,
}

impl EndToEndPublicKey {
    pub fn from_private_key(private_key: &EndToEndPrivateKey) -> EndToEndPublicKey {
        private_key.public_key()
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

impl Encode for EndToEndPublicKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.as_bytes().using_encoded(f)
    }
}

impl Decode for EndToEndPublicKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = <[u8; PUBLIC_KEY_SIZE]>::decode(input)?;
        let key = x25519_dalek::PublicKey::from(v);
        Ok(EndToEndPublicKey { key })
    }
}

#[derive(Zeroize, Clone, PartialEq, Eq, Debug)]
pub struct SharedSecret {
    secret: [u8; 32],
}

impl SharedSecret {
    pub fn encode_then_encrypt<T: Encode, R: Rng + CryptoRng>(
        &self,
        obj: &T,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        obj.using_encoded(|encoded| self.encrypt(encoded, rng))
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let symkey = symkey::SymmetricKey::from_raw_key(
            symkey::SymmetricKeyKind::XChacha20Poly1305,
            &self.secret,
        )
        .map_err(|e| Error::SymmetricKeyCreationFailed(e.to_string()))?;

        let cipher_text = symkey
            .encrypt(message, rng, None)
            .map_err(|e| Error::SymmetricEncryptionFailed(e.to_string()))?;

        Ok(cipher_text)
    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, Error> {
        let symkey = symkey::SymmetricKey::from_raw_key(
            symkey::SymmetricKeyKind::XChacha20Poly1305,
            &self.secret,
        )
        .map_err(|e| Error::SymmetricKeyCreationFailed(e.to_string()))?;

        let plain_text = symkey
            .decrypt(cipher_text, None)
            .map_err(|e| Error::SymmetricDecryptionFailed(e.to_string()))?;

        Ok(plain_text)
    }

    pub fn decrypt_then_decode<T: DecodeAll>(&self, cipher_text: &[u8]) -> Result<T, Error> {
        let decoded = self.decrypt(cipher_text)?;

        let obj = T::decode_all(&mut decoded.as_slice())
            .map_err(|e| Error::DeserializationFailed(e.to_string()))?;

        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn shared_secret_then_encrypt_decrypt(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let private_key1 = EndToEndPrivateKey::new_from_rng(&mut rng);
        let public_key1 = private_key1.public_key();
        let private_key2 = EndToEndPrivateKey::new_from_rng(&mut rng);
        let public_key2 = private_key2.public_key();

        let shared_secret1 = private_key1.shared_secret(&public_key2);
        let shared_secret2 = private_key2.shared_secret(&public_key1);
        assert_eq!(shared_secret1, shared_secret2);

        // One can decrypt their own cipher texts
        {
            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let cipher_text = shared_secret1.encrypt(&random_message, &mut rng).unwrap();
                let plain_text = shared_secret1.decrypt(&cipher_text).unwrap();
                assert_eq!(random_message, plain_text);
            }

            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let cipher_text = shared_secret2.encrypt(&random_message, &mut rng).unwrap();
                let plain_text = shared_secret2.decrypt(&cipher_text).unwrap();
                assert_eq!(random_message, plain_text);
            }
        }

        // One can decrypt others' cipher texts
        {
            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let cipher_text = shared_secret1.encrypt(&random_message, &mut rng).unwrap();
                let plain_text = shared_secret2.decrypt(&cipher_text).unwrap();
                assert_eq!(random_message, plain_text);
            }

            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let cipher_text = shared_secret2.encrypt(&random_message, &mut rng).unwrap();
                let plain_text = shared_secret1.decrypt(&cipher_text).unwrap();
                assert_eq!(random_message, plain_text);
            }
        }

        // One can decrypt others' encrypted objects
        {
            {
                let obj: String = (&mut rng)
                    .sample_iter(&randomness::distributions::Alphanumeric)
                    .take(100)
                    .map(char::from)
                    .collect();

                let cipher_text = shared_secret1.encode_then_encrypt(&obj, &mut rng).unwrap();
                let obj_decoded =
                    shared_secret2.decrypt_then_decode::<String>(&cipher_text).unwrap();
                assert_eq!(obj, obj_decoded);
            }

            {
                let obj: String = (&mut rng)
                    .sample_iter(&randomness::distributions::Alphanumeric)
                    .take(100)
                    .map(char::from)
                    .collect();

                let cipher_text = shared_secret2.encode_then_encrypt(&obj, &mut rng).unwrap();
                let obj_decoded =
                    shared_secret1.decrypt_then_decode::<String>(&cipher_text).unwrap();
                assert_eq!(obj, obj_decoded);
            }
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn shared_secret_then_encrypt_decrypt_tampered(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let private_key1 = EndToEndPrivateKey::new_from_rng(&mut rng);
        let public_key1 = private_key1.public_key();
        let private_key2 = EndToEndPrivateKey::new_from_rng(&mut rng);
        let public_key2 = private_key2.public_key();

        let shared_secret1 = private_key1.shared_secret(&public_key2);
        let shared_secret2 = private_key2.shared_secret(&public_key1);
        assert_eq!(shared_secret1, shared_secret2);

        // One cannot decrypt others' tampered cipher texts
        {
            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let mut cipher_text = shared_secret1.encrypt(&random_message, &mut rng).unwrap();
                let char_to_tamper_with = rng.gen_range(0..cipher_text.len());
                cipher_text[char_to_tamper_with] = cipher_text[char_to_tamper_with].wrapping_add(1);
                shared_secret2.decrypt(&cipher_text).unwrap_err();
            }

            {
                let random_message: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
                let mut cipher_text = shared_secret2.encrypt(&random_message, &mut rng).unwrap();
                let char_to_tamper_with = rng.gen_range(0..cipher_text.len());
                cipher_text[char_to_tamper_with] = cipher_text[char_to_tamper_with].wrapping_add(1);
                shared_secret1.decrypt(&cipher_text).unwrap_err();
            }
        }

        // One cannot decrypt others' tampered encrypted objects
        {
            {
                let obj: String = (&mut rng)
                    .sample_iter(&randomness::distributions::Alphanumeric)
                    .take(100)
                    .map(char::from)
                    .collect();

                let mut cipher_text = shared_secret1.encode_then_encrypt(&obj, &mut rng).unwrap();
                let char_to_tamper_with = rng.gen_range(0..cipher_text.len());
                cipher_text[char_to_tamper_with] = cipher_text[char_to_tamper_with].wrapping_add(1);
                shared_secret2.decrypt_then_decode::<String>(&cipher_text).unwrap_err();
            }

            {
                let obj: String = (&mut rng)
                    .sample_iter(&randomness::distributions::Alphanumeric)
                    .take(100)
                    .map(char::from)
                    .collect();

                let mut cipher_text = shared_secret2.encode_then_encrypt(&obj, &mut rng).unwrap();
                let char_to_tamper_with = rng.gen_range(0..cipher_text.len());
                cipher_text[char_to_tamper_with] = cipher_text[char_to_tamper_with].wrapping_add(1);
                shared_secret1.decrypt_then_decode::<String>(&cipher_text).unwrap_err();
            }
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn public_key_encode_decode(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let private_key = EndToEndPrivateKey::new_from_rng(&mut rng);
        let public_key = private_key.public_key();

        let encoded = public_key.encode();
        let decoded = EndToEndPublicKey::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(public_key, decoded);
    }
}
