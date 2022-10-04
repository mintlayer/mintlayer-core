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

use argon2::Argon2;

use super::KdfError;
use serialization::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Argon2Config {
    #[codec(compact)]
    pub m_cost_memory_size: u32,
    #[codec(compact)]
    pub t_cost_iterations: u32,
    #[codec(compact)]
    pub p_cost_parallelism: u32,
}

impl Argon2Config {
    pub fn new(m_cost_memory_size: u32, t_cost_iterations: u32, p_cost_parallelism: u32) -> Self {
        Self {
            m_cost_memory_size,
            t_cost_iterations,
            p_cost_parallelism,
        }
    }
}

pub fn argon2id_hash(
    config: &Argon2Config,
    salt: &[u8],
    desired_hash_len: NonZeroUsize,
    password: &[u8],
) -> Result<Vec<u8>, KdfError> {
    let params = argon2::Params::new(
        config.m_cost_memory_size,
        config.t_cost_iterations,
        config.p_cost_parallelism,
        Some(desired_hash_len.into()),
    )?;
    let context = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut result = vec![0; desired_hash_len.into()];
    context.hash_password_into(password, salt, &mut result)?;
    Ok(result)
}

#[cfg(test)]
pub mod test {
    use hex::ToHex;

    use super::*;

    // test values taken from https://argon2.online/

    #[test]
    fn chosen_text1() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(700, 16, 2),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "0b549350ae93d48747c5b3a676589279a3cce4a7b9de79494e2f0b7193d0ae9b"
        );
    }

    #[test]
    fn chosen_text2() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(400, 16, 2),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "f6acd6dc507655ef500975881f6ba642eb03d04ce71d3b3a139e04b321daa88a"
        );
    }

    #[test]
    fn chosen_text3() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(700, 12, 2),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "e57d0a6482f160a9f9f6c23f480eb478fcf5b13e07445514a7d4d6e48c52c5e3"
        );
    }

    #[test]
    fn chosen_text4() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(700, 16, 4),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "6e7833c72c1eaa5388b389f1cb657ee27858f062a164763d041c880fe7ced6d7"
        );
    }

    #[test]
    fn chosen_text5() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(700, 16, 6),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "8dd956b8a3d0e0a28905a70cff97a63ecc764af44b73daaef608de5a593e7ea7"
        );
    }

    #[test]
    fn chosen_text6() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(500, 16, 2),
            salt,
            32.try_into().unwrap(),
            b"password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "5aa54fa17129a5488e51a8c8ba6754921dfb0cbd88013942a4705ecb1789ab11"
        );
    }

    #[test]
    fn chosen_text7() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(500, 16, 2),
            salt,
            32.try_into().unwrap(),
            b"another password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "d3fd0dc78bceed1c87d303aaead74177676157bed51b9e5479e09c905c5bf2b4"
        );
    }

    #[test]
    fn chosen_text8() {
        let salt = b"some salt";
        let hash = argon2id_hash(
            &Argon2Config::new(500, 16, 2),
            salt,
            16.try_into().unwrap(),
            b"another password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(hash_hex, "1e67dcc183faab8ef49c5dcad921656d");
    }

    #[test]
    fn chosen_text9() {
        let salt = b"another salt";
        let hash = argon2id_hash(
            &Argon2Config::new(500, 16, 2),
            salt,
            32.try_into().unwrap(),
            b"another password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(
            hash_hex,
            "495205d26d5184c4b90e41c98cd067f85b67cc303d86391dfd16436f5d272e58"
        );
    }

    #[test]
    fn chosen_text10() {
        let salt = b"another salt";
        let hash = argon2id_hash(
            &Argon2Config::new(500, 16, 2),
            salt,
            16.try_into().unwrap(),
            b"another password",
        );
        let hash = hash.unwrap();
        let hash_hex: String = hash.encode_hex();
        assert_eq!(hash_hex, "24d0c2a85b9103e6adba63dcfaac86f7");
    }
}
