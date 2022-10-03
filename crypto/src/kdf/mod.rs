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

#[derive(Clone, Debug)]
pub enum KdfKind {
    Argon2id {
        m_cost_memory_size: u32,
        t_cost_iterations: u32,
        p_cost_parallelism: u32,
        hash_length: NonZeroUsize,
        salt_length: NonZeroUsize,
    },
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum KdfResult {
    Argon2id {
        m_cost_memory_size: u32,
        t_cost_iterations: u32,
        p_cost_parallelism: u32,
        salt: Vec<u8>,
        hashed_password: Vec<u8>,
    },
}

fn make_salt<R: Rng + CryptoRng>(rng: &mut R, len: NonZeroUsize) -> Result<Vec<u8>, KdfError> {
    let salt: Vec<u8> = (0..len.try_into().map_err(|_| KdfError::InvalidSaltSize)?)
        .map(|_| rng.gen::<u8>())
        .collect();
    Ok(salt)
}

pub fn hash_password<R: Rng + CryptoRng>(
    rng: &mut R,
    kdf: KdfKind,
    password: &[u8],
) -> Result<KdfResult, KdfError> {
    match kdf {
        KdfKind::Argon2id {
            m_cost_memory_size,
            t_cost_iterations,
            p_cost_parallelism,
            hash_length,
            salt_length,
        } => {
            let salt = make_salt(rng, salt_length)?;
            let hashed_password = argon2::argon2id_hash(
                m_cost_memory_size,
                t_cost_iterations,
                p_cost_parallelism,
                &salt,
                hash_length,
                password,
            )?;
            let result = KdfResult::Argon2id {
                m_cost_memory_size,
                t_cost_iterations,
                p_cost_parallelism,
                salt,
                hashed_password,
            };
            Ok(result)
        }
    }
}

pub fn verify_password(
    password: &[u8],
    previously_password_hash: KdfResult,
    equality_test_type: SliceEqualityCheckMethod,
) -> Result<bool, KdfError> {
    match previously_password_hash {
        KdfResult::Argon2id {
            m_cost_memory_size,
            t_cost_iterations,
            p_cost_parallelism,
            salt,
            hashed_password,
        } => {
            let new_hashed_password = argon2::argon2id_hash(
                m_cost_memory_size,
                t_cost_iterations,
                p_cost_parallelism,
                &salt,
                hashed_password.len().try_into().map_err(|_| KdfError::InvalidHashSize)?,
                password,
            )?;
            Ok(equality_test_type.is_equal(&new_hashed_password, &hashed_password))
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
        let password = b"SomeIncrediblyStrong___youGuessedIt___password";
        let kdf_kind = KdfKind::Argon2id {
            m_cost_memory_size: 200,
            t_cost_iterations: 10,
            p_cost_parallelism: 2,
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
}
