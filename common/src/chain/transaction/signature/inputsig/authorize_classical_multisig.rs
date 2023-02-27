use std::collections::BTreeMap;

use crypto::key::Signature;
use serialization::{Decode, Encode};

use crate::{
    chain::{classic_multisig::ClassicMultisigChallenge, signature::TransactionSigError},
    primitives::H256,
};

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedClassicalMultisigSpend {
    signatures: BTreeMap<u8, Signature>,
}

impl AuthorizedClassicalMultisigSpend {
    pub fn from_data(data: &Vec<u8>) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedClassicalMultisigSpend::decode(&mut data.as_slice())
            .map_err(|_| TransactionSigError::InvalidSignatureEncoding)?;
        Ok(decoded)
    }

    pub fn new(signatures: BTreeMap<u8, Signature>) -> Self {
        Self { signatures }
    }
}

pub fn verify_classical_multisig_spending(
    _spendee_pubkey: &ClassicMultisigChallenge,
    _spender_signature: &AuthorizedClassicalMultisigSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let _msg = sighash.encode();
    todo!("");
}
