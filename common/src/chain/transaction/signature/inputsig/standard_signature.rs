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

use std::io::BufWriter;

use serialization::{Decode, DecodeAll, Encode};

use crate::{
    chain::{
        signature::{
            sighashtype::{self, SigHashType},
            signature_hash, TransactionSigError,
        },
        ChainConfig, Destination, Transaction,
    },
    primitives::H256,
};

use super::{
    authorize_pubkey_spend::{
        sign_pubkey_spending, verify_public_key_spending, AuthorizedPublicKeySpend,
    },
    authorize_pubkeyhash_spend::{
        sign_address_spending, verify_address_spending, AuthorizedPublicKeyHashSpend,
    },
    classical_multisig::authorize_classical_multisig::{
        verify_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
    },
};

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
        chain_config: &ChainConfig,
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
            Destination::ClassicMultisig(c) => {
                let sig_components =
                    AuthorizedClassicalMultisigSpend::from_data(&self.raw_signature)?;
                verify_classical_multisig_spending(chain_config, c, &sig_components, sighash)?
            }
        }
        Ok(())
    }

    pub fn produce_uniparty_signature_for_input(
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
            Destination::ClassicMultisig(_) => todo!(),
        };
        Ok(Self {
            sighash_type,
            raw_signature: serialized_sig,
        })
    }

    pub fn raw_signature(&self) -> &Vec<u8> {
        &self.raw_signature
    }
}

impl Decode for StandardInputSignature {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let sighash_byte = input.read_byte()?;
        let sighash: sighashtype::SigHashType = sighash_byte
            .try_into()
            .map_err(|_| serialization::Error::from("Invalid sighash byte"))?;
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

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
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
        address::pubkeyhash::PublicKeyHash,
        chain::{
            config::create_mainnet,
            transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
        },
    };

    use super::*;
    use crate::chain::signature::{signature_hash, TransactionSigError};
    use crate::chain::Destination;
    use crypto::key::{KeyKind, PrivateKey};
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::Seed;

    const INPUT_NUM: usize = 0;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_address_missmatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let destination = Destination::Address(PublicKeyHash::from(&public_key));
        let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(TransactionSigError::PublicKeyToAddressMismatch),
                StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    INPUT_NUM,
                ),
                "{sighash_type:X?}"
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_key_missmatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(TransactionSigError::SpendeePrivatePublicKeyMismatch),
                StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    INPUT_NUM,
                ),
                "{sighash_type:X?}"
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_and_verify(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = create_mainnet();

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let outpoints = [
            Destination::Address(PublicKeyHash::from(&public_key)),
            Destination::PublicKey(public_key),
        ];

        for (sighash_type, destination) in sig_hash_types().cartesian_product(outpoints.into_iter())
        {
            let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();

            let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
            witness
                .verify_signature(&chain_config, &destination, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?} {destination:?}"));
        }
    }
}
