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

use std::num::NonZeroUsize;

use crate::{
    random::{CryptoRng, Rng},
    util::eq::SliceEqualityCheckMethod,
};
use serialization::{Decode, Encode};

use self::argon2::Argon2Config;

pub mod argon2;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum KdfError {
    #[error("Argon2 hashing error: {0}")]
    Argon2HashingFailed(#[from] ::argon2::Error),
    #[error("Invalid salt size")]
    InvalidSaltSize,
    #[error("Invalid hash size")]
    InvalidHashSize,
}

/// The object that contains the hashing configuration of every
/// supported algorithm
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdfConfig {
    Argon2id {
        config: Argon2Config,
        hash_length: NonZeroUsize,
        salt_length: NonZeroUsize,
    },
}

/// The result of hashing a password.
/// Note that the result stores the hashed password as it's appropriate
/// for client/server authentication. To use this for encryption,
/// call the function into_challenge() to remove the hashed password.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub enum KdfResult {
    #[codec(index = 0)]
    Argon2id {
        config: Argon2Config,
        salt: Vec<u8>,
        hashed_password: Vec<u8>,
    },
}

impl KdfResult {
    /// Removes the hashed password from a hashing operation.
    /// This is appropriate for storage as header for encrypted
    /// data (such as wallets, where the hashed password is the
    /// symmetric encryption key)
    pub fn into_challenge(self) -> KdfChallenge {
        match self {
            KdfResult::Argon2id {
                config,
                salt,
                hashed_password,
            } => KdfChallenge::Argon2id {
                config,
                salt,
                password_hash_len: hashed_password.len() as u32,
            },
        }
    }
}

/// The object to be stored to be able to recalculate the encryption key.
/// This is appropriate for storage in wallets as header.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub enum KdfChallenge {
    #[codec(index = 0)]
    Argon2id {
        config: Argon2Config,
        salt: Vec<u8>,
        #[codec(compact)]
        password_hash_len: u32,
    },
}

fn make_salt<R: Rng + CryptoRng>(rng: &mut R, len: NonZeroUsize) -> Result<Vec<u8>, KdfError> {
    let len = len.try_into().map_err(|_| KdfError::InvalidSaltSize)?;
    let salt: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
    Ok(salt)
}

/// Recalculate a previously hashed password to recover an encryption key
/// for a decryption operation.
/// The idea is that the KdfChallenge can be deserialized from some header,
/// and then directly used with a password to re-derive the encryption key.
pub fn hash_from_challenge(
    challenge: KdfChallenge,
    password: &[u8],
) -> Result<KdfResult, KdfError> {
    match challenge {
        KdfChallenge::Argon2id {
            config,
            salt,
            password_hash_len,
        } => {
            let hashed_password = argon2::argon2id_hash(
                &config,
                &salt,
                (password_hash_len as usize).try_into().map_err(|_| KdfError::InvalidHashSize)?,
                password,
            )?;
            let result = KdfResult::Argon2id {
                config,
                salt,
                hashed_password,
            };
            Ok(result)
        }
    }
}

/// Hash a password using any provided kdf-configuration
/// The result from this function is appropriate only for
/// client/server applications. To use this for encryption,
/// convert the result into a challenge using into_challenge(),
/// which removes the hashed password.
pub fn hash_password<R: Rng + CryptoRng>(
    rng: &mut R,
    kdf_config: KdfConfig,
    password: &[u8],
) -> Result<KdfResult, KdfError> {
    match kdf_config {
        KdfConfig::Argon2id {
            config,
            hash_length,
            salt_length,
        } => {
            let salt = make_salt(rng, salt_length)?;
            let hashed_password = argon2::argon2id_hash(&config, &salt, hash_length, password)?;
            let result = KdfResult::Argon2id {
                config,
                salt,
                hashed_password,
            };
            Ok(result)
        }
    }
}

/// Verify a password in a client/server setup by comparing its hash to the stored value
pub fn verify_password(
    password: &[u8],
    previously_password_hash: KdfResult,
    equality_checker: SliceEqualityCheckMethod,
) -> Result<bool, KdfError> {
    match previously_password_hash {
        KdfResult::Argon2id {
            config,
            salt,
            hashed_password,
        } => {
            let new_hashed_password = argon2::argon2id_hash(
                &config,
                &salt,
                hashed_password.len().try_into().map_err(|_| KdfError::InvalidHashSize)?,
                password,
            )?;
            Ok(equality_checker.are_equal(&new_hashed_password, &hashed_password))
        }
    }
}

#[cfg(test)]
pub mod test {
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn salt_generation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let salt1 = make_salt(&mut rng, 32.try_into().unwrap()).unwrap();
        let salt2 = make_salt(&mut rng, 32.try_into().unwrap()).unwrap();
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn password_hash_generation_argon2id(#[case] seed: Seed) {
        let password = b"SomeIncrediblyStrong___youGuessedIt___password!";
        let kdf_kind = KdfConfig::Argon2id {
            config: Argon2Config {
                m_cost_memory_size: 200,
                t_cost_iterations: 10,
                p_cost_parallelism: 2,
            },
            hash_length: 32.try_into().unwrap(),
            salt_length: 16.try_into().unwrap(),
        };

        let mut rng = make_seedable_rng(seed);
        let password_hash = hash_password(&mut rng, kdf_kind, password).unwrap();
        assert!(verify_password(
            password,
            password_hash.clone(),
            SliceEqualityCheckMethod::Normal
        )
        .unwrap());
        assert!(verify_password(
            password,
            password_hash.clone(),
            SliceEqualityCheckMethod::TimingResistant
        )
        .unwrap());

        let wrong_password = b"RandomWrong____password?";
        assert!(!verify_password(
            wrong_password,
            password_hash.clone(),
            SliceEqualityCheckMethod::Normal
        )
        .unwrap());
        assert!(!verify_password(
            wrong_password,
            password_hash,
            SliceEqualityCheckMethod::TimingResistant
        )
        .unwrap());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn conversion_to_challenge(#[case] seed: Seed) {
        let password = b"SomeIncrediblyStrong___youGuessedIt___password!";
        let kdf_kind = KdfConfig::Argon2id {
            config: Argon2Config {
                m_cost_memory_size: 200,
                t_cost_iterations: 10,
                p_cost_parallelism: 2,
            },
            hash_length: 32.try_into().unwrap(),
            salt_length: 16.try_into().unwrap(),
        };

        let mut rng = make_seedable_rng(seed);
        let password_hash = hash_password(&mut rng, kdf_kind, password).unwrap();
        assert!(verify_password(
            password,
            password_hash.clone(),
            SliceEqualityCheckMethod::Normal
        )
        .unwrap());
        assert!(verify_password(
            password,
            password_hash.clone(),
            SliceEqualityCheckMethod::TimingResistant
        )
        .unwrap());

        let challenge = password_hash.into_challenge();

        let challenge_recreated = hash_from_challenge(challenge.clone(), password).unwrap();

        assert_eq!(challenge_recreated.into_challenge(), challenge);
    }
}
