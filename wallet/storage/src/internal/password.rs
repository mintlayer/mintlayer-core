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

use crypto::{
    kdf::{
        argon2::Argon2Config, hash_from_challenge, hash_password, KdfChallenge, KdfConfig,
        KdfResult,
    },
    random::make_true_rng,
    symkey::{key_size, SymmetricKey, SymmetricKeyKind},
};
use utils::const_nz_usize;

/// Converts a password into a symmetric encryption key and generates a KDF challenge.
///
/// # Arguments
///
/// * `password` - A `String` representing the password to convert into a symmetric encryption key.
///
/// # Returns
///
/// This function returns a tuple `(SymmetricKey, KdfChallenge)`, where `SymmetricKey` is the derived
/// encryption key and `KdfChallenge` is the generated challenge value.
///
pub fn password_to_sym_key(password: &String) -> crate::Result<(SymmetricKey, KdfChallenge)> {
    if password.is_empty() {
        return Err(crate::Error::WalletEmptyPassword);
    }

    let mut rng = make_true_rng();
    let config = KdfConfig::Argon2id {
        // TODO: hardcoded values
        config: Argon2Config::new(16384, 4, 4),
        hash_length: const_nz_usize!(key_size(SymmetricKeyKind::XChacha20Poly1305)),
        salt_length: const_nz_usize!(32),
    };
    let kdf_result = hash_password(&mut rng, config, password.as_bytes())
        .map_err(|_| crate::Error::WalletInvalidPassword)?;
    let KdfResult::Argon2id {
        hashed_password,
        config: _,
        salt: _,
    } = &kdf_result;

    let sym_key = SymmetricKey::from_raw_key(
        SymmetricKeyKind::XChacha20Poly1305,
        hashed_password.as_slice(),
    )
    .expect("must be correct size");

    let challenge = kdf_result.into_challenge();

    Ok((sym_key, challenge))
}

/// Derives a symmetric encryption key from a password and a KDF challenge.
///
/// This function takes a password and a KDF challenge as input and derives a symmetric encryption key
/// using a key derivation function (KDF). The KDF challenge is used to authenticate the derived key
/// during decryption.
///
/// # Arguments
///
/// * `password` - A `String` representing the password to derive the symmetric encryption key.
/// * `kdf_challenge` - A `KdfChallenge` representing the challenge used for key derivation.
///
/// # Returns
///
/// This function returns a `SymmetricKey`, which is the derived encryption key.
/// Returns an WalletInvalidPassword error if the password did not pass the challenge
///
pub fn challenge_to_sym_key(
    password: &String,
    kdf_challenge: KdfChallenge,
) -> crate::Result<SymmetricKey> {
    let KdfResult::Argon2id {
        hashed_password,
        salt: _,
        config: _,
    } = hash_from_challenge(kdf_challenge, password.as_bytes())
        .map_err(|_| crate::Error::WalletInvalidPassword)?;

    let sym_key = SymmetricKey::from_raw_key(
        SymmetricKeyKind::XChacha20Poly1305,
        hashed_password.as_slice(),
    )
    .expect("must be correct size");

    Ok(sym_key)
}

#[cfg(test)]
mod test {
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::{challenge_to_sym_key, password_to_sym_key};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_password_to_challenge_and_back(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let password: String = (0..rng.gen_range(1..100)).map(|_| rng.gen::<char>()).collect();
        let (original_key, kdf_challenge) = password_to_sym_key(&password).unwrap();

        let reconstructed_key = challenge_to_sym_key(&password, kdf_challenge).unwrap();

        assert_eq!(original_key, reconstructed_key);
    }

    #[test]
    fn test_empty_password_error() {
        let password = String::new();
        let result = password_to_sym_key(&password);

        assert_eq!(result, Err(crate::Error::WalletEmptyPassword));
    }
}
