// Copyright (c) 2025 RBB S.r.l
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

use std::{collections::BTreeMap, num::NonZeroU8};

use itertools::Itertools as _;
use randomness::seq::IteratorRandom;
use rstest::rstest;

use crypto::key::{KeyKind, PrivateKey};
use logging::log;
use randomness::Rng;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        config::create_unit_test_config,
        htlc::HtlcSecret,
        output_value::OutputValue,
        signature::{
            inputsig::{
                authorize_hashed_timelock_contract_spend::{
                    AuthorizedHashedTimelockContractSpend, AuthorizedHashedTimelockContractSpendTag,
                },
                authorize_pubkey_spend::{sign_public_key_spending, AuthorizedPublicKeySpend},
                authorize_pubkeyhash_spend::sign_public_key_hash_spending,
                classical_multisig::authorize_classical_multisig::{
                    sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                },
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::sighashtype::SigHashType,
        },
        Destination, OutPointSourceId, SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
    size_estimation::{
        input_signature_size_from_destination, tx_size_with_num_inputs_and_outputs,
        DestinationInfoProvider, MultisigInfo,
    },
};

struct TestDestInfoProvider(BTreeMap<Destination, MultisigInfo>);

impl DestinationInfoProvider for TestDestInfoProvider {
    fn get_multisig_info(&self, destination: &Destination) -> Option<MultisigInfo> {
        self.0.get(destination).cloned()
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn estimate_tx_size_basic(
    #[case] seed: Seed,
    #[values(1..64, 64..0x4000, 0x4000..0x4001)] inputs_range: std::ops::Range<u32>,
    #[values(1..64, 64..0x4000, 0x4000..0x4001)] outputs_range: std::ops::Range<u32>,
) {
    let mut rng = make_seedable_rng(seed);

    let num_inputs = rng.gen_range(inputs_range);
    let inputs = (0..num_inputs)
        .map(|_| {
            TxInput::from_utxo(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.gen_range(0..100),
            )
        })
        .collect();

    let num_outputs = rng.gen_range(outputs_range);
    let outputs = (0..num_outputs)
        .map(|_| {
            let destination = Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            );

            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..10000))),
                destination,
            )
        })
        .collect();

    let tx = Transaction::new(0, inputs, outputs).unwrap();
    let signatures_with_dests = (0..num_inputs)
        .map(|_| {
            let (prv_key, pub_key) =
                PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);
            let signature = prv_key.sign_message(&[0; 32], &mut rng).unwrap();
            let raw_signature = AuthorizedPublicKeySpend::new(signature).encode();
            let standard = StandardInputSignature::new(SigHashType::all(), raw_signature);
            let dest = Destination::PublicKey(pub_key);
            (InputWitness::Standard(standard), dest)
        })
        .collect_vec();
    let signatures = signatures_with_dests.iter().map(|(sig, _)| sig.clone()).collect_vec();
    let tx = SignedTransaction::new(tx, signatures).unwrap();

    let base_tx_size =
        tx_size_with_num_inputs_and_outputs(num_outputs as usize, num_inputs as usize).unwrap();
    let inputs_size = tx.inputs().iter().map(Encode::encoded_size).sum::<usize>();
    let outputs_size = tx.outputs().iter().map(Encode::encoded_size).sum::<usize>();

    let signatures_size = signatures_with_dests
        .iter()
        .map(|(_, dest)| input_signature_size_from_destination(dest, None, None).unwrap())
        .sum::<usize>();

    let estimated_tx_size = base_tx_size + inputs_size + signatures_size + outputs_size;
    let actual_tx_size = Encode::encoded_size(&tx);

    assert_eq!(estimated_tx_size, actual_tx_size);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn estimate_tx_size_different_sigs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();

    let num_inputs = rng.gen_range(1..10);
    let inputs = (0..num_inputs)
        .map(|_| {
            TxInput::from_utxo(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.gen_range(0..100),
            )
        })
        .collect();

    let num_outputs = rng.gen_range(1..10);
    let outputs = (0..num_outputs)
        .map(|_| {
            let destination = Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            );

            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..10000))),
                destination,
            )
        })
        .collect();

    let mut dest_info_provider = TestDestInfoProvider(BTreeMap::new());

    let tx = Transaction::new(0, inputs, outputs).unwrap();
    let signatures_with_dests = (0..num_inputs)
        .map(|_| {
            let (raw_sig, destination) = match rng.gen_range(0..3) {
                0 => {
                    let (prv_key, pub_key) =
                        PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);

                    let sighash = H256::random_using(&mut rng);
                    let spending =
                        sign_public_key_spending(&prv_key, &pub_key, &sighash, &mut rng).unwrap();

                    (spending.encode(), Destination::PublicKey(pub_key))
                }
                1 => {
                    let (prv_key, pub_key) =
                        PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr);

                    let sighash = H256::random_using(&mut rng);
                    let pubkeyhash: PublicKeyHash = (&pub_key).into();
                    let spending =
                        sign_public_key_hash_spending(&prv_key, &pubkeyhash, &sighash, &mut rng)
                            .unwrap();

                    (spending.encode(), Destination::PublicKeyHash(pubkeyhash))
                }
                _ => {
                    let max_sig_count: u8 = rng
                        .gen_range(2..=chain_config.max_classic_multisig_public_keys_count())
                        .try_into()
                        .unwrap();
                    let min_sig_count = rng.gen_range(1..=max_sig_count);

                    let keys = (0..max_sig_count)
                        .map(|_| {
                            PrivateKey::new_from_rng(
                                &mut rng,
                                crypto::key::KeyKind::Secp256k1Schnorr,
                            )
                        })
                        .collect_vec();

                    let challenge = ClassicMultisigChallenge::new(
                        &chain_config,
                        NonZeroU8::new(min_sig_count).unwrap(),
                        keys.iter().map(|(_, pubkey)| pubkey.clone()).collect_vec(),
                    )
                    .unwrap();

                    let keys_with_indices =
                        keys.iter().enumerate().choose_multiple(&mut rng, min_sig_count as usize);

                    let mut spending =
                        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());
                    let sighash = H256::random_using(&mut rng);

                    for (loop_idx, (key_idx, (prv_key, _))) in keys_with_indices.iter().enumerate()
                    {
                        let spending_status = sign_classical_multisig_spending(
                            &chain_config,
                            *key_idx as u8,
                            prv_key,
                            &challenge,
                            &sighash,
                            spending,
                            &mut rng,
                        )
                        .unwrap();

                        if loop_idx == keys_with_indices.len() - 1 {
                            assert!(spending_status.is_complete());
                        } else {
                            assert!(!spending_status.is_complete());
                        }

                        spending = spending_status.take();
                    }

                    let destination = Destination::ClassicMultisig((&challenge).into());

                    dest_info_provider.0.insert(
                        destination.clone(),
                        MultisigInfo::from_challenge(&challenge),
                    );

                    (spending.encode(), destination)
                }
            };

            let (raw_sig, htlc_spend_tag) = match rng.gen_range(0..3) {
                0 => (raw_sig, None),
                1 => {
                    let secret = HtlcSecret::new(rng.gen());
                    let raw_sig =
                        AuthorizedHashedTimelockContractSpend::Spend(secret, raw_sig).encode();

                    (
                        raw_sig,
                        Some(AuthorizedHashedTimelockContractSpendTag::Spend),
                    )
                }
                _ => {
                    let raw_sig = AuthorizedHashedTimelockContractSpend::Refund(raw_sig).encode();

                    (
                        raw_sig,
                        Some(AuthorizedHashedTimelockContractSpendTag::Refund),
                    )
                }
            };

            let witness =
                InputWitness::Standard(StandardInputSignature::new(SigHashType::all(), raw_sig));

            (witness, destination, htlc_spend_tag)
        })
        .collect_vec();

    log::debug!("signatures_with_dests = {signatures_with_dests:?}");

    let signatures = signatures_with_dests.iter().map(|(sig, _, _)| sig.clone()).collect_vec();
    let tx = SignedTransaction::new(tx, signatures).unwrap();

    let base_tx_size =
        tx_size_with_num_inputs_and_outputs(num_outputs as usize, num_inputs as usize).unwrap();
    let inputs_size = tx.inputs().iter().map(Encode::encoded_size).sum::<usize>();
    let outputs_size = tx.outputs().iter().map(Encode::encoded_size).sum::<usize>();

    let signatures_size = signatures_with_dests
        .iter()
        .map(|(_, dest, htlc_spend_tag)| {
            input_signature_size_from_destination(dest, *htlc_spend_tag, Some(&dest_info_provider))
                .unwrap()
        })
        .sum::<usize>();

    let estimated_tx_size = base_tx_size + inputs_size + signatures_size + outputs_size;
    let actual_tx_size = Encode::encoded_size(&tx);

    assert_eq!(estimated_tx_size, actual_tx_size);
}
