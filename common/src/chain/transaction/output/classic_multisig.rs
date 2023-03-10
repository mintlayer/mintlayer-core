// Copyright (c) 2021-2023 RBB S.r.l
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

use std::num::NonZeroU8;

use crypto::key::PublicKey;
use serialization::{Decode, Encode};

use crate::chain::ChainConfig;

/// A challenge represented by a set of public keys and a minimum number of signatures required to pass the challenge.
/// Keep in mind that this object must be checked on construction using `is_valid` to ensure that it follows the rules
/// of the blockchain. An invalid object can still be constructed with deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct ClassicMultisigChallenge {
    min_required_signatures: u8,
    public_keys: Vec<PublicKey>,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ClassicMultisigChallengeError {
    #[error("Too many public keys, more than allowed: {0} > {1}")]
    TooManyPublicKeys(usize, usize),
    #[error("More required signatures than public keys: {0} > {1}")]
    MoreRequiredSignaturesThanPublicKeys(u8, usize),
    #[error("Public keys vector is empty")]
    EmptyPublicKeys,
    #[error("Minimum required signatures is 0")]
    MinRequiredSignaturesIsZero,
}

impl ClassicMultisigChallenge {
    pub fn new(
        chain_config: &ChainConfig,
        min_required_signatures: NonZeroU8,
        public_keys: Vec<PublicKey>,
    ) -> Result<Self, ClassicMultisigChallengeError> {
        let res = Self {
            min_required_signatures: min_required_signatures.get(),
            public_keys,
        };
        res.is_valid(chain_config)?;
        Ok(res)
    }

    pub fn is_valid(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<(), ClassicMultisigChallengeError> {
        if self.public_keys.is_empty() {
            return Err(ClassicMultisigChallengeError::EmptyPublicKeys);
        }
        if self.public_keys.len() > chain_config.max_classic_multisig_public_keys_count() {
            return Err(ClassicMultisigChallengeError::TooManyPublicKeys(
                self.public_keys.len(),
                chain_config.max_classic_multisig_public_keys_count(),
            ));
        }

        if self.min_required_signatures == 0 {
            return Err(ClassicMultisigChallengeError::MinRequiredSignaturesIsZero);
        }

        if self.min_required_signatures as usize > self.public_keys.len() {
            return Err(
                ClassicMultisigChallengeError::MoreRequiredSignaturesThanPublicKeys(
                    self.min_required_signatures,
                    self.public_keys.len(),
                ),
            );
        }

        Ok(())
    }

    pub fn min_required_signatures(&self) -> u8 {
        self.min_required_signatures
    }

    pub fn public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }
}

#[cfg(test)]
mod tests {
    use crypto::key::{KeyKind, PrivateKey};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;
    use crate::chain::config::create_mainnet;

    #[test]
    fn zero_pub_keys() {
        let chain_config = create_mainnet();

        // Notice that we circumvent the constructor because this struct can be decoded from data
        let res = ClassicMultisigChallenge {
            min_required_signatures: 1,
            public_keys: vec![],
        };

        assert_eq!(
            res.is_valid(&chain_config).unwrap_err(),
            ClassicMultisigChallengeError::EmptyPublicKeys
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn min_required_signatures_is_zero(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();

        // Notice that we circumvent the constructor because this struct can be decoded from data
        let res = ClassicMultisigChallenge {
            min_required_signatures: 0,
            public_keys: vec![PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1],
        };

        assert_eq!(
            res.is_valid(&chain_config).unwrap_err(),
            ClassicMultisigChallengeError::MinRequiredSignaturesIsZero
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn more_required_signatures_than_public_keys(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();

        let pub_key_count = 1 + rng.gen::<u8>() % 10;

        let min_required_signatures = pub_key_count + 1;

        let public_keys = (0..pub_key_count)
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1)
            .collect::<Vec<_>>();

        // Notice that we circumvent the constructor because this struct can be decoded from data
        let res = ClassicMultisigChallenge {
            min_required_signatures,
            public_keys,
        };

        assert_eq!(
            res.is_valid(&chain_config).unwrap_err(),
            ClassicMultisigChallengeError::MoreRequiredSignaturesThanPublicKeys(
                pub_key_count + 1,
                res.public_keys.len()
            )
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn too_many_public_keys(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();

        let pub_key_count = 1 + chain_config.max_classic_multisig_public_keys_count() as u8;

        let min_required_signatures = 1 + rng.gen::<u8>() % pub_key_count;

        let public_keys = (0..pub_key_count)
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1)
            .collect::<Vec<_>>();

        // Notice that we circumvent the constructor because this struct can be decoded from data
        let res = ClassicMultisigChallenge {
            min_required_signatures,
            public_keys,
        };

        assert_eq!(
            res.is_valid(&chain_config).unwrap_err(),
            ClassicMultisigChallengeError::TooManyPublicKeys(
                res.public_keys.len(),
                chain_config.max_classic_multisig_public_keys_count()
            )
        );
    }
}
