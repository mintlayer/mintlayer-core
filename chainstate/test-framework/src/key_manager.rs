// Copyright (c) 2024 RBB S.r.l
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

use serialization::Encode;
use std::{collections::BTreeMap, num::NonZeroU8};

use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        signature::{
            inputsig::{
                classical_multisig::authorize_classical_multisig::{
                    sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                    ClassicalMultisigCompletionStatus,
                },
                htlc::produce_classical_multisig_signature_for_htlc_input,
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::{
                input_commitments::SighashInputCommitment, sighashtype::SigHashType, signature_hash,
            },
        },
        ChainConfig, Destination, Transaction, TxOutput,
    },
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};
use randomness::{CryptoRng, Rng};

#[derive(Clone)]
struct Multisig {
    keys: Vec<(PrivateKey, PublicKey)>,
    min_required_signatures: NonZeroU8,
}

impl Multisig {
    fn challenge(&self, chain_config: &ChainConfig) -> ClassicMultisigChallenge {
        ClassicMultisigChallenge::new(
            chain_config,
            self.min_required_signatures,
            self.keys.iter().map(|k| k.1.clone()).collect(),
        )
        .unwrap()
    }
}

#[derive(Clone)]
pub struct KeyManager {
    public_key_hashes: BTreeMap<PublicKeyHash, PrivateKey>,
    public_keys: BTreeMap<PublicKey, PrivateKey>,
    multisigs: BTreeMap<PublicKeyHash, Multisig>,
}

impl KeyManager {
    pub fn new<'a>(private_keys: impl Iterator<Item = &'a PrivateKey>) -> Self {
        Self {
            public_keys: private_keys
                .map(|pk| (PublicKey::from_private_key(pk), pk.clone()))
                .collect(),
            public_key_hashes: BTreeMap::new(),
            multisigs: BTreeMap::new(),
        }
    }

    pub fn new_destination(
        &mut self,
        chain_config: &ChainConfig,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Destination {
        match rng.gen_range(0..5) {
            0 => {
                let (private_key, public_key) =
                    PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
                let public_key_hash: PublicKeyHash = (&public_key).into();
                self.public_key_hashes.insert(public_key_hash, private_key);
                Destination::PublicKeyHash(public_key_hash)
            }
            1 => {
                let (private_key, public_key) =
                    PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
                self.public_keys.insert(public_key.clone(), private_key);
                Destination::PublicKey(public_key)
            }
            2 => {
                let min_required_signatures = rng.gen_range(1..32);
                let num_pub_keys = rng.gen_range(min_required_signatures..=32);
                let keys: Vec<_> = (0..num_pub_keys)
                    .map(|_| PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr))
                    .collect();
                let pub_keys = keys.iter().map(|k| k.1.clone()).collect();
                let min_required_signatures = NonZeroU8::new(min_required_signatures).unwrap();
                let challenge =
                    ClassicMultisigChallenge::new(chain_config, min_required_signatures, pub_keys)
                        .unwrap();
                let multisig_hash: PublicKeyHash = (&challenge).into();
                self.multisigs.insert(
                    multisig_hash,
                    Multisig {
                        keys,
                        min_required_signatures,
                    },
                );
                Destination::ClassicMultisig(multisig_hash)
            }
            // 3 => Destination::ScriptHash(Id::new(H256::from_slice(&rng.gen::<[u8; 32]>()))),
            _ => Destination::AnyoneCanSpend,
        }
    }

    pub fn new_2_of_2_multisig_destination(
        &mut self,
        chain_config: &ChainConfig,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Destination {
        let min_required_signatures = 2;
        let num_pub_keys = 2;
        let keys: Vec<_> = (0..num_pub_keys)
            .map(|_| PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr))
            .collect();
        let pub_keys = keys.iter().map(|k| k.1.clone()).collect();
        let min_required_signatures = NonZeroU8::new(min_required_signatures).unwrap();
        let challenge =
            ClassicMultisigChallenge::new(chain_config, min_required_signatures, pub_keys).unwrap();
        let multisig_hash: PublicKeyHash = (&challenge).into();
        self.multisigs.insert(
            multisig_hash,
            Multisig {
                keys,
                min_required_signatures,
            },
        );
        Destination::ClassicMultisig(multisig_hash)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_signature(
        &self,
        rng: &mut (impl Rng + CryptoRng),
        destination: &Destination,
        chain_config: &ChainConfig,
        tx: &Transaction,
        input_commitments: &[SighashInputCommitment],
        input_num: usize,
        input_utxo: Option<&TxOutput>,
    ) -> Option<InputWitness> {
        match destination {
            Destination::AnyoneCanSpend => Some(InputWitness::NoSignature(None)),
            Destination::PublicKey(pub_key) => {
                let private_key = self.public_keys.get(pub_key).unwrap();
                let sighash_type = SigHashType::all();

                let sig = StandardInputSignature::produce_uniparty_signature_for_input(
                    private_key,
                    sighash_type,
                    destination.clone(),
                    tx,
                    input_commitments,
                    input_num,
                    rng,
                )
                .map(InputWitness::Standard)
                .unwrap();
                Some(sig)
            }
            Destination::PublicKeyHash(pub_key) => {
                let private_key = self.public_key_hashes.get(pub_key).unwrap();
                let sighash_type = SigHashType::all();

                let sig = StandardInputSignature::produce_uniparty_signature_for_input(
                    private_key,
                    sighash_type,
                    destination.clone(),
                    tx,
                    input_commitments,
                    input_num,
                    rng,
                )
                .map(InputWitness::Standard)
                .unwrap();
                Some(sig)
            }
            Destination::ClassicMultisig(multisig) => {
                let multisig = &self.multisigs.get(multisig).unwrap();
                let challenge = multisig.challenge(chain_config);
                let mut current_signatures =
                    AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());
                let sighash_type = SigHashType::all();

                let sighash =
                    signature_hash(sighash_type, tx, input_commitments, input_num).unwrap();

                for (key_index, (private_key, _pub_key)) in multisig.keys.iter().enumerate() {
                    let res = sign_classical_multisig_spending(
                        chain_config,
                        key_index as u8,
                        private_key,
                        &challenge,
                        &sighash,
                        current_signatures,
                        rng,
                    )
                    .unwrap();

                    match res {
                        ClassicalMultisigCompletionStatus::Complete(sigs) => {
                            let sig = if input_utxo.is_some_and(is_htlc_output) {
                                produce_classical_multisig_signature_for_htlc_input(
                                    chain_config,
                                    &sigs,
                                    sighash_type,
                                    tx,
                                    input_commitments,
                                    input_num,
                                )
                                .unwrap()
                            } else {
                                StandardInputSignature::new(sighash_type, sigs.encode())
                            };

                            return Some(InputWitness::Standard(sig));
                        }
                        ClassicalMultisigCompletionStatus::Incomplete(sigs) => {
                            current_signatures = sigs;
                        }
                    };
                }
                panic!("could not sign multisig input");
            }
            Destination::ScriptHash(_) => None,
        }
    }
}

fn is_htlc_output(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => false,
        TxOutput::Htlc(_, _) => true,
    }
}
