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

mod authorize_address_spend;
mod authorize_pubkey_spend;

use std::io::BufWriter;

use parity_scale_codec::{Decode, DecodeAll, Encode};

use crate::{
    chain::{ChainConfig, Destination, Transaction},
    primitives::H256,
};

use self::{
    authorize_address_spend::{
        sign_address_spending, verify_address_spending, AuthorizedAddressSpend,
    },
    authorize_pubkey_spend::{
        sign_pubkey_spending, verify_public_key_spending, AuthorizedPublicKeySpend,
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

    pub fn get_sighash_type(&self) -> SigHashType {
        self.sighash_type
    }

    pub fn from_data<T: AsRef<[u8]>>(raw_data: T) -> Result<Self, TransactionSigError> {
        let decoded_sig = StandardInputSignature::decode_all(raw_data.as_ref())
            .map_err(|_| TransactionSigError::DecodingWitnessFailed)?;
        Ok(decoded_sig)
    }

    pub fn verify_signature(
        &self,
        chain_config: &ChainConfig,
        outpoint_destination: &Destination,
        sighash: &H256,
    ) -> Result<(), TransactionSigError> {
        match outpoint_destination {
            Destination::Address(addr) => {
                let sig_components = AuthorizedAddressSpend::from_data(&self.raw_signature)?;
                verify_address_spending(chain_config, addr, &sig_components, sighash)?
            }
            Destination::PublicKey(pubkey) => {
                let sig_components = AuthorizedPublicKeySpend::from_data(&self.raw_signature)?;
                verify_public_key_spending(pubkey, &sig_components, sighash)?
            }
            Destination::ScriptHash(_) => return Err(TransactionSigError::Unsupported),
        }
        Ok(())
    }

    pub fn produce_signature_for_input(
        chain_config: &ChainConfig,
        private_key: &crypto::key::PrivateKey,
        sighash_type: sighashtype::SigHashType,
        outpoint_destination: Destination,
        tx: &Transaction,
        input_num: usize,
    ) -> Result<Self, TransactionSigError> {
        let sighash = signature_hash(sighash_type, tx, input_num)?;
        let serialized_sig = match outpoint_destination {
            Destination::Address(ref addr) => {
                let sig = sign_address_spending(private_key, chain_config, addr, &sighash)?;
                sig.encode()
            }
            Destination::PublicKey(ref pubkey) => {
                let sig = sign_pubkey_spending(private_key, pubkey, &sighash)?;
                sig.encode()
            }
            Destination::ScriptHash(_) => return Err(TransactionSigError::Unsupported),
        };
        Ok(Self {
            sighash_type,
            raw_signature: serialized_sig,
        })
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

// TODO: write tests

#[cfg(test)]
mod test {
    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
