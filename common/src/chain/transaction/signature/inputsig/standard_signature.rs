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

use crypto::key::SigAuxDataProvider;
use serialization::{Decode, DecodeAll, Encode};

use crate::{
    chain::{
        signature::{
            sighash::{
                input_commitments::SighashInputCommitment, sighashtype::SigHashType, signature_hash,
            },
            DestinationSigError, Signable,
        },
        ChainConfig, Destination, Transaction,
    },
    primitives::H256,
};

use super::{
    authorize_pubkey_spend::{
        sign_public_key_spending, verify_public_key_spending, AuthorizedPublicKeySpend,
    },
    authorize_pubkeyhash_spend::{
        sign_public_key_hash_spending, verify_public_key_hash_spending,
        AuthorizedPublicKeyHashSpend,
    },
    classical_multisig::{
        authorize_classical_multisig::{
            verify_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
        },
        multisig_partial_signature::PartiallySignedMultisigChallenge,
    },
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, serde::Serialize)]
pub struct StandardInputSignature {
    sighash_type: SigHashType,
    raw_signature: Vec<u8>,
}

impl StandardInputSignature {
    pub fn new(sighash_type: SigHashType, raw_signature: Vec<u8>) -> Self {
        Self {
            sighash_type,
            raw_signature,
        }
    }

    pub fn sighash_type(&self) -> SigHashType {
        self.sighash_type
    }

    pub fn from_data<T: AsRef<[u8]>>(raw_data: T) -> Result<Self, DestinationSigError> {
        let decoded_sig = StandardInputSignature::decode_all(&mut raw_data.as_ref())
            .map_err(|_| DestinationSigError::DecodingWitnessFailed)?;
        Ok(decoded_sig)
    }

    pub fn verify_signature(
        &self,
        chain_config: &ChainConfig,
        outpoint_destination: &Destination,
        sighash: &H256,
    ) -> Result<(), DestinationSigError> {
        match outpoint_destination {
            Destination::PublicKeyHash(addr) => {
                let sig_components = AuthorizedPublicKeyHashSpend::from_data(&self.raw_signature)?;
                verify_public_key_hash_spending(addr, &sig_components, sighash)?
            }
            Destination::PublicKey(pubkey) => {
                let sig_components = AuthorizedPublicKeySpend::from_data(&self.raw_signature)?;
                verify_public_key_spending(pubkey, &sig_components, sighash)?
            }
            Destination::ScriptHash(_) => return Err(DestinationSigError::Unsupported),
            Destination::AnyoneCanSpend => {
                // AnyoneCanSpend must use InputWitness::NoSignature, so this is unreachable
                return Err(
                    DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
                );
            }
            Destination::ClassicMultisig(h) => {
                let sig_components =
                    AuthorizedClassicalMultisigSpend::from_data(&self.raw_signature)?;
                verify_classical_multisig_spending(chain_config, h, &sig_components, sighash)?
            }
        }
        Ok(())
    }

    pub fn produce_uniparty_signature_for_input<T: Signable, AuxP: SigAuxDataProvider + ?Sized>(
        private_key: &crypto::key::PrivateKey,
        sighash_type: SigHashType,
        outpoint_destination: Destination,
        tx: &T,
        input_commitments: &[SighashInputCommitment],
        input_index: usize,
        sig_aux_data_provider: &mut AuxP,
    ) -> Result<Self, DestinationSigError> {
        let sighash = signature_hash(sighash_type, tx, input_commitments, input_index)?;
        let serialized_sig = match outpoint_destination {
            Destination::PublicKeyHash(ref addr) => {
                let sig = sign_public_key_hash_spending(private_key, addr, &sighash, sig_aux_data_provider)?;
                sig.encode()
            }
            Destination::PublicKey(ref pubkey) => {
                let sig = sign_public_key_spending(private_key, pubkey, &sighash, sig_aux_data_provider)?;
                sig.encode()
            }
            Destination::ScriptHash(_) => return Err(DestinationSigError::Unsupported),
            Destination::AnyoneCanSpend => {
                // AnyoneCanSpend must use InputWitness::NoSignature, so this is unreachable
                return Err(DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend);
            }
            Destination::ClassicMultisig(_) => return Err(
                // This function doesn't support this kind of signature
                DestinationSigError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
            ),
        };

        Ok(Self {
            sighash_type,
            raw_signature: serialized_sig,
        })
    }

    pub fn produce_classical_multisig_signature_for_input(
        chain_config: &ChainConfig,
        authorization: &AuthorizedClassicalMultisigSpend,
        sighash_type: SigHashType,
        tx: &Transaction,
        input_commitments: &[SighashInputCommitment],
        input_index: usize,
    ) -> Result<Self, DestinationSigError> {
        use super::classical_multisig::multisig_partial_signature::SigsVerifyResult;

        let sighash = signature_hash(sighash_type, tx, input_commitments, input_index)?;
        let message = sighash.encode();

        let verifier =
            PartiallySignedMultisigChallenge::from_partial(chain_config, &message, authorization)?;

        let verification_result = verifier.verify_signatures(chain_config)?;

        match verification_result {
            SigsVerifyResult::CompleteAndValid => (),
            SigsVerifyResult::Incomplete => {
                return Err(DestinationSigError::IncompleteClassicalMultisigAuthorization)
            }
            SigsVerifyResult::Invalid => {
                return Err(DestinationSigError::InvalidClassicalMultisigAuthorization)
            }
        }

        let serialized_sig = authorization.encode();

        Ok(Self {
            sighash_type,
            raw_signature: serialized_sig,
        })
    }

    pub fn raw_signature(&self) -> &[u8] {
        &self.raw_signature
    }

    pub fn into_raw_signature(self) -> Vec<u8> {
        self.raw_signature
    }
}

impl Decode for StandardInputSignature {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let sighash_byte = input.read_byte()?;
        let sighash: SigHashType = sighash_byte
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
            signature::{sighash::signature_hash, DestinationSigError},
            transaction::signature::tests::utils::{
                generate_input_commitments, generate_unsigned_tx, sig_hash_types,
            },
            Destination,
        },
    };

    use super::*;
    use crypto::key::{KeyKind, PrivateKey};
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::Seed;

    const INPUT_NUM: usize = 0;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_pub_key_hash_mismatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));

        let input_commitments = generate_input_commitments(&mut rng, 1);

        let tx = generate_unsigned_tx(&mut rng, &destination, input_commitments.len(), 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(DestinationSigError::PublicKeyToHashMismatch),
                StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    &input_commitments,
                    INPUT_NUM,
                    &mut rng,
                ),
                "{sighash_type:X?}"
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_key_mismatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKey(public_key);

        let input_commitments = generate_input_commitments(&mut rng, 1);

        let tx = generate_unsigned_tx(&mut rng, &destination, input_commitments.len(), 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(DestinationSigError::SpendeePrivatePublicKeyMismatch),
                StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    &input_commitments,
                    INPUT_NUM,
                    &mut rng
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
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let outpoints = [
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            Destination::PublicKey(public_key),
        ];

        for (sighash_type, destination) in sig_hash_types().cartesian_product(outpoints.into_iter())
        {
            let input_commitments = generate_input_commitments(&mut rng, 1);

            let tx =
                generate_unsigned_tx(&mut rng, &destination, input_commitments.len(), 2).unwrap();
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &input_commitments,
                INPUT_NUM,
                &mut rng,
            )
            .unwrap();

            let sighash =
                signature_hash(witness.sighash_type(), &tx, &input_commitments, INPUT_NUM).unwrap();
            witness
                .verify_signature(&chain_config, &destination, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?} {destination:?}"));
        }
    }
}
