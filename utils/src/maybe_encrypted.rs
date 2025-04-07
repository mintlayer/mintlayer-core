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

use std::marker::PhantomData;

use crypto::symkey::SymmetricKey;
use randomness::make_true_rng;
use serialization::{Decode, DecodeAll, Encode};
use zeroize::Zeroizing;

use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum MaybeEncryptedError {
    #[error("Error in decryption: {0}")]
    DecryptionError(#[from] crypto::symkey::Error),

    #[error("Error in decoding: {0}")]
    DecodingError(#[from] serialization::Error),
}

/// A generic helper type that is used to encode/decode and optionally encrypt/decrypt a type T
#[derive(Encode, Decode)]
pub struct MaybeEncrypted<T> {
    value: Vec<u8>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T: Encode + DecodeAll> MaybeEncrypted<T> {
    /// Creates a new `MaybeEncrypted` instance with the given value and encryption key.
    ///
    /// If the encryption key is `Some`, the value will be encrypted using the key.
    /// If the encryption key is `None`, the value will be stored as plain bytes.
    pub fn new(value: &T, encryption_key: &Option<SymmetricKey>) -> Self {
        match encryption_key {
            Some(key) => Self::new_encrypted(value, key),
            None => Self::new_plain(value),
        }
    }

    fn new_plain(value: &T) -> Self {
        Self {
            value: value.encode(),
            _phantom: Default::default(),
        }
    }

    fn new_encrypted(value: &T, encryption_key: &SymmetricKey) -> Self {
        Self {
            value: encryption_key
                .encrypt(
                    Zeroizing::new(value.encode()).as_slice(),
                    &mut make_true_rng(),
                    None,
                )
                .expect("should not fail"),
            _phantom: Default::default(),
        }
    }

    /// Attempts to take the value from the `MaybeEncrypted` instance.
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - An optional `SymmetricKey`
    ///   If the encryption key is `Some`, the value will be decrypted using the key before decoding.
    ///   If the encryption key is `None`, the value is assumed to be plain bytes and decoded as is.
    ///
    /// # Returns
    ///
    /// Returns an `MaybeEncryptedError::DecryptionError` if the `encryption_key` is wrong
    /// Returns an `MaybeEncryptedError::DecodingError` if the MaybeEncrypted object was decoded
    /// from an invalid slice of bytes
    pub fn try_take(self, encryption_key: &Option<SymmetricKey>) -> Result<T, MaybeEncryptedError> {
        match encryption_key {
            Some(key) => self.try_decrypt_then_take(key),
            None => self.try_take_plain(),
        }
    }

    fn try_take_plain(self) -> Result<T, MaybeEncryptedError> {
        T::decode_all(&mut self.value.as_slice()).map_err(MaybeEncryptedError::from)
    }

    pub fn try_decrypt_then_take(
        self,
        encryption_key: &SymmetricKey,
    ) -> Result<T, MaybeEncryptedError> {
        let decrypted_bytes = encryption_key.decrypt(self.value.as_slice(), None)?;
        T::decode_all(&mut Zeroizing::new(decrypted_bytes).as_slice())
            .map_err(MaybeEncryptedError::from)
    }
}

#[cfg(test)]
mod tests {
    use crypto::symkey::SymmetricKeyKind;
    use randomness::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[test]
    fn test_new_plain_and_back() {
        let value = 42;
        let maybe_encrypted = MaybeEncrypted::new(&value, &None);

        assert_eq!(maybe_encrypted.try_take(&None).unwrap(), value);
    }

    #[test]
    fn test_new_plain_and_back_plain() {
        let value = 42;
        let maybe_encrypted = MaybeEncrypted::new(&value, &None);

        assert_eq!(maybe_encrypted.try_take_plain().unwrap(), value);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_new_plain_and_back_decrypted_error(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let value = rng.gen::<u32>();
        let maybe_encrypted = MaybeEncrypted::new(&value, &None);

        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let key = Some(key);

        assert!(maybe_encrypted.try_take(&key).is_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_new_encrypted_and_back(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let value = rng.gen::<u32>();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let key = Some(key);
        let maybe_encrypted = MaybeEncrypted::new(&value, &key);

        assert_eq!(maybe_encrypted.try_take(&key).unwrap(), value);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_new_encrypted_and_back_no_key_error(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let value = rng.gen::<u32>();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let key = Some(key);
        let maybe_encrypted = MaybeEncrypted::new(&value, &key);

        assert!(maybe_encrypted.try_take(&None).is_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_new_encrypted_and_back_different_key_error(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let value = rng.gen::<u32>();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let key = Some(key);
        let maybe_encrypted = MaybeEncrypted::new(&value, &key);

        let mut different_key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        while &different_key == key.as_ref().unwrap() {
            different_key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        }
        let different_key = Some(different_key);

        assert!(maybe_encrypted.try_take(&different_key).is_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_wrong_encode_decode(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let value = rng.gen::<u32>();

        let optional_key = if rng.gen::<bool>() {
            Some(SymmetricKey::new(
                SymmetricKeyKind::XChacha20Poly1305,
                &mut rng,
            ))
        } else {
            None
        };

        let maybe_encrypted = MaybeEncrypted::new(&value, &optional_key);

        let bytes = maybe_encrypted.encode();

        let wrong_type = MaybeEncrypted::<u64>::decode(&mut bytes.as_slice()).unwrap();

        match wrong_type.try_take(&optional_key) {
            Err(MaybeEncryptedError::DecodingError(_)) => {}
            _ => panic!("wrong error"),
        }
    }
}
