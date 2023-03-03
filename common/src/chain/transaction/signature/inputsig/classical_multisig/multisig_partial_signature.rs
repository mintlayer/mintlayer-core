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

use crate::chain::{
    classic_multisig::{ClassicMultisigChallenge, ClassicMultisigChallengeError},
    ChainConfig,
};

use super::authorize_classical_multisig::AuthorizedClassicalMultisigSpend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartiallySignedMultisigChallenge<'a> {
    /// The signatures that have been added to this challenge. The indices are the indices of the public keys.
    signatures: &'a AuthorizedClassicalMultisigSpend,
    /// The message that is being signed.
    message: &'a [u8],
    /// The challenge that is being signed.
    challenge: &'a ClassicMultisigChallenge,
}

impl<'a> PartiallySignedMultisigChallenge<'a> {
    pub fn from_partial(
        chain_config: &ChainConfig,
        challenge: &'a ClassicMultisigChallenge,
        message: &'a [u8],
        signatures: &'a AuthorizedClassicalMultisigSpend,
    ) -> Result<Self, PartiallySignedMultisigStructureError> {
        let result = PartiallySignedMultisigChallenge {
            signatures,
            challenge,
            message,
        };
        result.check_structurally_valid(chain_config)?;
        Ok(result)
    }

    pub fn challenge(&self) -> &ClassicMultisigChallenge {
        self.challenge
    }

    pub fn signatures(&self) -> &AuthorizedClassicalMultisigSpend {
        self.signatures
    }

    pub fn missing_signatures_count(&self) -> i32 {
        self.challenge.min_required_signatures() as i32
            - self.signatures.available_signatures_count() as i32
    }

    /// Check whether the structure of the multisig challenge and signatures is valid, but without validating signatures
    pub fn check_structurally_valid(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<PartiallySignedMultisigState, PartiallySignedMultisigStructureError> {
        if let Err(err) = self.challenge.is_valid(chain_config) {
            return Err(PartiallySignedMultisigStructureError::InvalidChallenge(err));
        }

        if self
            .signatures
            .public_key_indices()
            .any(|index| index as usize >= self.challenge.public_keys().len())
        {
            return Err(PartiallySignedMultisigStructureError::InvalidSignatureIndex);
        }

        let missing_signatures_count = self.missing_signatures_count();
        match missing_signatures_count.cmp(&0) {
            std::cmp::Ordering::Less => {
                Err(PartiallySignedMultisigStructureError::Overconstrained(
                    self.signatures.available_signatures_count(),
                    self.challenge.min_required_signatures() as usize,
                ))
            }
            std::cmp::Ordering::Equal => Ok(PartiallySignedMultisigState::Complete(
                self.signatures.available_signatures_count(),
            )),
            std::cmp::Ordering::Greater => Ok(PartiallySignedMultisigState::Incomplete(
                self.signatures.available_signatures_count(),
                self.challenge.min_required_signatures() as usize,
            )),
        }
    }

    pub fn verify_signatures(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<SigsVerifyResult, PartiallySignedMultisigStructureError> {
        self.check_structurally_valid(chain_config)?;

        if self.signatures.is_empty() {
            return Ok(SigsVerifyResult::Incomplete);
        }

        let verification_result = self.signatures.iter().all(|(index, signature)| {
            let public_key = &self.challenge.public_keys()[index as usize];
            public_key.verify_message(signature, self.message)
        });

        if self.signatures().available_signatures_count()
            < self.challenge.min_required_signatures() as usize
        {
            return Ok(SigsVerifyResult::Incomplete);
        }

        match verification_result {
            false => Ok(SigsVerifyResult::Invalid),
            true => Ok(SigsVerifyResult::CompleteAndValid),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum PartiallySignedMultisigStructureError {
    #[error("Too many signatures have been added to the challenge: {0} > {1}")]
    Overconstrained(usize, usize),
    #[error("The challenge is structurally invalid and can never be used for signing: {0}")]
    InvalidChallenge(#[from] ClassicMultisigChallengeError),
    #[error("The challenge contains a signature for a public key that does not exist")]
    InvalidSignatureIndex,
}

pub enum PartiallySignedMultisigState {
    /// Not enough signatures have been added to the challenge.
    Incomplete(usize, usize),
    /// Enough signatures have been added to the challenge.
    Complete(usize),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigsVerifyResult {
    /// The challenge is structurally valid, and all signatures have been added.
    CompleteAndValid,
    /// The challenge is structurally valid, but not all signatures have been added.
    Incomplete,
    /// The challenge is structurally invalid but the signatures are invalid.
    Invalid,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU8;

    use crypto::key::{KeyKind, PrivateKey, Signature};
    use crypto::random::{Rng, SliceRandom};
    use rstest::rstest;

    use crate::chain::config::create_mainnet;
    use crate::primitives::H256;
    use serialization::Encode;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    fn test_valid_challenge(
        rng: &mut impl Rng,
        chain_config: &ChainConfig,
        signatures_map: &BTreeMap<u8, Signature>,
        challenge: &ClassicMultisigChallenge,
        message_bytes: &[u8],
        priv_keys: &[PrivateKey],
    ) {
        // Valid cases with incomplete and complete signatures
        for sig_count in 0..priv_keys.len() {
            let mut signatures_map =
                signatures_map.clone().into_iter().take(sig_count).collect::<Vec<(_, _)>>();
            signatures_map.shuffle(rng);
            let signatures_map = signatures_map.into_iter().collect::<BTreeMap<_, _>>();

            let auth = AuthorizedClassicalMultisigSpend::new(signatures_map);

            let sigs = PartiallySignedMultisigChallenge::from_partial(
                chain_config,
                &challenge,
                &message_bytes,
                &auth,
            );

            let sigs = match sigs {
                Ok(sigs) => {
                    assert!(sig_count as u8 <= challenge.min_required_signatures());
                    sigs
                }
                Err(err) => {
                    assert!(
                        err == PartiallySignedMultisigStructureError::Overconstrained(
                            sig_count,
                            challenge.min_required_signatures() as usize
                        )
                    );
                    continue;
                }
            };

            if sig_count as u8 == challenge.min_required_signatures() {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::CompleteAndValid
                );
            } else {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::Incomplete
                );
            }
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn signature_validity(#[case] seed: Seed) {
        let chain_config = &create_mainnet();

        let mut rng = make_seedable_rng(seed);
        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties = (rng.gen::<u8>() % 10) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .into_iter()
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(chain_config, min_required_signatures, pub_keys).unwrap();
        challenge.is_valid(chain_config).unwrap();

        let message = H256::random_using(&mut rng);
        let message_bytes = message.encode();

        let signatures_map = priv_keys
            .iter()
            .enumerate()
            .map(|(index, priv_key)| {
                let signature = priv_key.sign_message(&message.encode()).unwrap();
                (index as u8, signature)
            })
            .collect::<BTreeMap<_, _>>();

        test_valid_challenge(
            &mut rng,
            chain_config,
            &signatures_map,
            &challenge,
            &message_bytes,
            &priv_keys,
        );

        // Tampered with sigs
        for sig_count in 1..priv_keys.len() {
            let mut signatures_map =
                signatures_map.clone().into_iter().take(sig_count).collect::<Vec<(_, _)>>();
            signatures_map.shuffle(&mut rng);
            let tampered_pair_ref = signatures_map.choose_mut(&mut rng).unwrap();
            let tampered_index = tampered_pair_ref.0;
            let tampered_signature = priv_keys[tampered_index as usize]
                .sign_message(&H256::random_using(&mut rng).encode())
                .unwrap();
            // replace the signatures with a tampered one
            tampered_pair_ref.1 = tampered_signature;

            let signatures_map = signatures_map.into_iter().collect::<BTreeMap<_, _>>();

            let auth = AuthorizedClassicalMultisigSpend::new(signatures_map);

            let sigs = PartiallySignedMultisigChallenge::from_partial(
                chain_config,
                &challenge,
                &message_bytes,
                &auth,
            );

            let sigs = match sigs {
                Ok(sigs) => {
                    assert!(sig_count as u8 <= challenge.min_required_signatures());
                    sigs
                }
                Err(err) => {
                    assert!(
                        err == PartiallySignedMultisigStructureError::Overconstrained(
                            sig_count,
                            challenge.min_required_signatures() as usize
                        )
                    );
                    continue;
                }
            };

            if sig_count as u8 == challenge.min_required_signatures() {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::Invalid
                );
            } else {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::Incomplete
                );
            }
        }

        // Sign with wrong key
        for sig_count in 1..priv_keys.len() {
            let mut signatures_map =
                signatures_map.clone().into_iter().take(sig_count).collect::<Vec<(_, _)>>();
            signatures_map.shuffle(&mut rng);
            let tampered_pair_ref = signatures_map.choose_mut(&mut rng).unwrap();
            let wrong_signature = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr)
                .0
                .sign_message(&H256::random_using(&mut rng).encode())
                .unwrap();
            // replace the signatures with a tampered one
            tampered_pair_ref.1 = wrong_signature;

            let signatures_map = signatures_map.into_iter().collect::<BTreeMap<_, _>>();

            let auth = AuthorizedClassicalMultisigSpend::new(signatures_map);

            let sigs = PartiallySignedMultisigChallenge::from_partial(
                chain_config,
                &challenge,
                &message_bytes,
                &auth,
            );

            let sigs = match sigs {
                Ok(sigs) => {
                    assert!(sig_count as u8 <= challenge.min_required_signatures());
                    sigs
                }
                Err(err) => {
                    assert!(
                        err == PartiallySignedMultisigStructureError::Overconstrained(
                            sig_count,
                            challenge.min_required_signatures() as usize
                        )
                    );
                    continue;
                }
            };

            if sig_count as u8 == challenge.min_required_signatures() {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::Invalid
                );
            } else {
                assert_eq!(
                    sigs.verify_signatures(chain_config).unwrap(),
                    SigsVerifyResult::Incomplete
                );
            }
        }
    }
}
