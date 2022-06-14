// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

mod authorize_pubkey_spend;
mod authorize_pubkeyhash_spend;

use std::io::BufWriter;

use parity_scale_codec::{Decode, DecodeAll, Encode};

use crate::{
    chain::{Destination, Transaction},
    primitives::H256,
};

use self::{
    authorize_pubkey_spend::{
        sign_pubkey_spending, verify_public_key_spending, AuthorizedPublicKeySpend,
    },
    authorize_pubkeyhash_spend::{
        sign_address_spending, verify_address_spending, AuthorizedPublicKeyHashSpend,
    },
};

use super::{
    sighashtype::{self, SigHashType},
    signature_hash, TransactionSigError,
};

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum InputWitness {
    #[codec(index = 0)]
    NoSignature(Option<Vec<u8>>),
    #[codec(index = 1)]
    Standard(StandardInputSignature),
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct StandardInputSignature {
    sighash_type: SigHashType,
    raw_signature: Vec<u8>,
}

impl StandardInputSignature {
    pub fn new(sighash_type: sighashtype::SigHashType, raw_signature: Vec<u8>) -> Self {
        Self {
            sighash_type,
            raw_signature,
        }
    }

    pub fn sighash_type(&self) -> SigHashType {
        self.sighash_type
    }

    pub fn from_data<T: AsRef<[u8]>>(raw_data: T) -> Result<Self, TransactionSigError> {
        let decoded_sig = StandardInputSignature::decode_all(&mut raw_data.as_ref())
            .map_err(|_| TransactionSigError::DecodingWitnessFailed)?;
        Ok(decoded_sig)
    }

    pub fn verify_signature(
        &self,
        outpoint_destination: &Destination,
        sighash: &H256,
    ) -> Result<(), TransactionSigError> {
        match outpoint_destination {
            Destination::Address(addr) => {
                let sig_components = AuthorizedPublicKeyHashSpend::from_data(&self.raw_signature)?;
                verify_address_spending(addr, &sig_components, sighash)?
            }
            Destination::PublicKey(pubkey) => {
                let sig_components = AuthorizedPublicKeySpend::from_data(&self.raw_signature)?;
                verify_public_key_spending(pubkey, &sig_components, sighash)?
            }
            Destination::ScriptHash(_) => return Err(TransactionSigError::Unsupported),
            Destination::AnyoneCanSpend => {
                // AnyoneCanSpend must use InputWitness::NoSignature, so this is unreachable
                return Err(
                    TransactionSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
                );
            }
        }
        Ok(())
    }

    pub fn produce_signature_for_input(
        private_key: &crypto::key::PrivateKey,
        sighash_type: sighashtype::SigHashType,
        outpoint_destination: Destination,
        tx: &Transaction,
        input_num: usize,
    ) -> Result<Self, TransactionSigError> {
        let sighash = signature_hash(sighash_type, tx, input_num)?;
        let serialized_sig = match outpoint_destination {
            Destination::Address(ref addr) => {
                let sig = sign_address_spending(private_key, addr, &sighash)?;
                sig.encode()
            }
            Destination::PublicKey(ref pubkey) => {
                let sig = sign_pubkey_spending(private_key, pubkey, &sighash)?;
                sig.encode()
            }
            Destination::ScriptHash(_) => return Err(TransactionSigError::Unsupported),

            Destination::AnyoneCanSpend => {
                // AnyoneCanSpend must use InputWitness::NoSignature, so this is unreachable
                return Err(TransactionSigError::AttemptedToProduceSignatureForAnyoneCanSpend);
            }
        };
        Ok(Self {
            sighash_type,
            raw_signature: serialized_sig,
        })
    }

    pub fn get_raw_signature(&self) -> &Vec<u8> {
        &self.raw_signature
    }
}

impl Decode for StandardInputSignature {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let sighash_byte = input.read_byte()?;
        let sighash: sighashtype::SigHashType = sighash_byte
            .try_into()
            .map_err(|_| parity_scale_codec::Error::from("Invalid sighash byte"))?;
        let raw_sig = Vec::decode(input)?;

        Ok(Self {
            sighash_type: sighash,
            raw_signature: raw_sig,
        })
    }
}

impl Encode for StandardInputSignature {
    fn encode(&self) -> Vec<u8> {
        let mut buf = BufWriter::new(Vec::new());
        self.encode_to(&mut buf);
        buf.into_inner().expect("Flushing should never fail")
    }

    fn size_hint(&self) -> usize {
        self.raw_signature.size_hint() + 1
    }

    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&[self.sighash_type.get()]);
        self.raw_signature.encode_to(dest);
    }

    fn encoded_size(&self) -> usize {
        self.raw_signature.encoded_size() + 1
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chain::{TransactionCreationError, TxInput, TxOutput},
        primitives::{Amount, Id},
    };

    use super::*;
    use crypto::key::{KeyKind, PrivateKey};

    fn generate_unsigned_tx(
        outpoint_dest: Destination,
    ) -> Result<Transaction, TransactionCreationError> {
        let tx = Transaction::new(
            0,
            vec![TxInput::new(
                Id::<Transaction>::new(&H256::zero()).into(),
                0,
                InputWitness::NoSignature(None),
            )],
            vec![TxOutput::new(Amount::from_atoms(100), outpoint_dest)],
            0,
        )?;
        Ok(tx)
    }

    #[test]
    fn test_produce_and_verify() {
        const INPUT_NUM: usize = 0;
        // ALL
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(outpoint_destination.clone()).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();

        // ALL | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();

        // NONE
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(outpoint_destination.clone()).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();

        // NONE | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();

        // SINGLE
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(outpoint_destination.clone()).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();

        // SINGLE | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_destination.clone(),
            &tx,
            INPUT_NUM,
        )
        .unwrap();

        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        witness.verify_signature(&outpoint_destination, &sighash).unwrap();
    }
}
