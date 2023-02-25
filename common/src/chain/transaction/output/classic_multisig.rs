use std::num::NonZeroU32;

use parity_scale_codec::{Decode, Encode};

use crate::{address::pubkeyhash::PublicKeyHash, chain::ChainConfig};

/// A challenge represented by a set of public keys and a minimum number of signatures required to pass the challenge.
/// The public keys are hashed for privacy.
/// Keep in mind that this object must be checked on construction using `is_valid` to ensure that it follows the rules
/// of the blockchain. An invalid object can still be constructed with deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct ClassicMultisigChallenge {
    min_required_signatures: NonZeroU32,
    public_keys_hashes: Vec<PublicKeyHash>,
}

// TODO(PR): add a check in consensus that the number of public keys is not too large

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ClassicMultisigChallengeError {
    #[error("Too many public keys, more than allowed: {0} > {1}")]
    TooManyPublicKeys(usize, usize),
    #[error("More required signatures than public keys: {0} > {1}")]
    MoreRequiredSignaturesThanPublicKeys(NonZeroU32, usize),
    #[error("Public keys hashes vector is empty")]
    EmptyPublicKeys,
}

impl ClassicMultisigChallenge {
    pub fn new(
        chain_config: &ChainConfig,
        min_required_signatures: NonZeroU32,
        public_keys: Vec<PublicKeyHash>,
    ) -> Result<Self, ClassicMultisigChallengeError> {
        let res = Self {
            min_required_signatures,
            public_keys_hashes: public_keys,
        };
        res.is_valid(chain_config)?;
        return Ok(res);
    }

    pub fn is_valid(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<(), ClassicMultisigChallengeError> {
        if self.public_keys_hashes.is_empty() {
            return Err(ClassicMultisigChallengeError::EmptyPublicKeys);
        }
        if self.public_keys_hashes.len() > chain_config.max_classic_multisig_public_keys_count() {
            return Err(ClassicMultisigChallengeError::TooManyPublicKeys(
                self.public_keys_hashes.len(),
                chain_config.max_classic_multisig_public_keys_count(),
            ));
        }
        if self.min_required_signatures.get() as usize > self.public_keys_hashes.len() {
            return Err(
                ClassicMultisigChallengeError::MoreRequiredSignaturesThanPublicKeys(
                    self.min_required_signatures,
                    self.public_keys_hashes.len(),
                ),
            );
        }

        Ok(())
    }

    pub fn min_required_signatures(&self) -> NonZeroU32 {
        self.min_required_signatures
    }

    pub fn public_keys(&self) -> &[PublicKeyHash] {
        &self.public_keys_hashes
    }
}
