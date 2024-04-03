// Copyright (c) 2022 RBB S.r.l
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

use std::vec;

use itertools::Itertools;
use rstest::rstest;

use self::utils::*;
use super::{inputsig::InputWitness, sighash::sighashtype::SigHashType};
use crate::{
    chain::{
        config::create_mainnet,
        output_value::OutputValue,
        signature::{
            inputsig::standard_signature::StandardInputSignature, verify_signature,
            DestinationSigError,
        },
        signed_transaction::SignedTransaction,
        ChainConfig, Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::CryptoRng;
use randomness::Rng;
use test_utils::random::Seed;

mod mixed_sighash_types;
mod sign_and_mutate;
mod sign_and_verify;

pub mod utils;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_and_verify_different_sighash_types(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let tx = generate_and_sign_tx(
            &chain_config,
            &mut rng,
            &destination,
            &inputs_utxos,
            3,
            &private_key,
            sighash_type,
        )
        .unwrap();
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        assert_eq!(
            verify_signed_tx(&chain_config, &tx, &inputs_utxos_refs, &destination),
            Ok(()),
            "{sighash_type:?}"
        );
    }
}

// Trying to verify a transaction without signature should produce the corresponding error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_no_signature(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    for destination in
        destinations(&mut rng, public_key).filter(|d| d != &Destination::AnyoneCanSpend)
    {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, 3).unwrap();
        let witnesses = (0..tx.inputs().len())
            .map(|_| InputWitness::NoSignature(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9])))
            .collect_vec();
        let signed_tx = tx.with_signatures(witnesses).unwrap();
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &signed_tx,
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureNotFound),
            "{destination:?}"
        );
    }
}

// Try to verify empty and wrong (arbitrary bytes) signatures.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_invalid_signature(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let empty_signature = vec![];
    let invalid_signature = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

    for (sighash_type, raw_signature) in
        sig_hash_types().cartesian_product([empty_signature, invalid_signature])
    {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, 3).unwrap();
        let witnesses = (0..tx.inputs().len())
            .map(|_| {
                InputWitness::Standard(StandardInputSignature::new(
                    sighash_type,
                    raw_signature.clone(),
                ))
            })
            .collect_vec();
        let signed_tx = tx.with_signatures(witnesses).unwrap();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &signed_tx,
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::InvalidSignatureEncoding),
            "{sighash_type:?}, signature = {raw_signature:?}"
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_signature_invalid_signature_index(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    const INVALID_SIGNATURE_INDEX: usize = 1234567890;

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = generate_and_sign_tx(
            &chain_config,
            &mut rng,
            &destination,
            &inputs_utxos,
            3,
            &private_key,
            sighash_type,
        )
        .unwrap();
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx,
                &inputs_utxos_refs,
                INVALID_SIGNATURE_INDEX
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                INVALID_SIGNATURE_INDEX,
                3
            )),
            "{sighash_type:?}"
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_signature_wrong_destination(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint = Destination::PublicKey(public_key);

    let (_, public_key_2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let different_outpoint = Destination::PublicKey(public_key_2);

    for sighash_type in sig_hash_types() {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = generate_and_sign_tx(
            &chain_config,
            &mut rng,
            &outpoint,
            &inputs_utxos,
            3,
            &private_key,
            sighash_type,
        )
        .unwrap();
        assert_eq!(
            verify_signature(
                &chain_config,
                &different_outpoint,
                &tx,
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
            "{sighash_type:?}"
        );
    }
}

// ALL applies to all inputs and outputs, so changing or adding anything makes it invalid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_all(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
}

// ALL|ANYONECANPAY applies to one input and all outputs, so adding input is ok, but anything else isn't.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_all_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
}

// NONE is applied to all inputs and none of the outputs, so the latter can be changed in any way.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_none(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
}

// NONE|ANYONECANPAY is applied to only one input, so changing everything else is OK.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_none_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
}

// SINGLE is applied to all inputs and one output, so only adding an output is OK.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_single(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
}

// SINGLE|ANYONECANPAY is applied to one input and one output so adding inputs and outputs is OK.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_single_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let original_tx = sign_mutate_then_verify(
        &chain_config,
        &mut rng,
        &inputs_utxos,
        &private_key,
        sighash_type,
        &outpoint_dest,
    );

    check_insert_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_input(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
    check_insert_output(
        &chain_config,
        &mut rng,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        false,
    );
    check_mutate_output(
        &chain_config,
        &original_tx,
        &inputs_utxos_refs,
        &outpoint_dest,
        true,
    );
}

fn sign_mutate_then_verify(
    chain_config: &ChainConfig,
    rng: &mut (impl Rng + CryptoRng),
    inputs_utxos: &[Option<TxOutput>],
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    destination: &Destination,
) -> SignedTransaction {
    // Create and sign tx, and then modify and verify it.
    let original_tx = generate_and_sign_tx(
        chain_config,
        rng,
        destination,
        inputs_utxos,
        3,
        private_key,
        sighash_type,
    )
    .unwrap();
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    assert_eq!(
        verify_signed_tx(chain_config, &original_tx, &inputs_utxos_refs, destination),
        Ok(())
    );

    check_change_flags(chain_config, &original_tx, &inputs_utxos_refs, destination);
    check_mutate_witness(chain_config, &original_tx, &inputs_utxos_refs, destination);
    check_mutate_inputs_utxos(chain_config, &original_tx, &inputs_utxos_refs, destination);
    original_tx
}

fn check_change_flags(
    chain_config: &ChainConfig,
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    destination: &Destination,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = tx_updater.flags.wrapping_add(1234567890);
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(chain_config, destination, &tx, inputs_utxos, input_num),
            Err(DestinationSigError::SignatureVerificationFailed)
        );
    }
}

fn check_insert_input(
    chain_config: &ChainConfig,
    rng: &mut (impl Rng + CryptoRng),
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    destination: &Destination,
    should_fail: bool,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let outpoint_source_id =
        OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(rng)));

    let inputs_utxo = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(123)),
        Destination::AnyoneCanSpend,
    );
    let mut inputs_utxos = inputs_utxos.to_vec();
    inputs_utxos.push(Some(&inputs_utxo));

    tx_updater.inputs.push(TxInput::from_utxo(outpoint_source_id, 1));
    tx_updater.witness.push(InputWitness::NoSignature(Some(vec![1, 2, 3])));
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(chain_config, destination, &tx, &inputs_utxos, 0);
    if should_fail {
        assert_eq!(res, Err(DestinationSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

// A witness mutation should result in signature verification error.
fn check_mutate_witness(
    chain_config: &ChainConfig,
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    outpoint_dest: &Destination,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    for input in 0..original_tx.inputs().len() {
        let signature = match &tx_updater.witness[0] {
            InputWitness::Standard(signature) => signature,
            InputWitness::NoSignature(_) => panic!("Unexpected InputWitness::NoSignature"),
        };

        let raw_signature = signature.raw_signature().iter().map(|b| b.wrapping_add(1)).collect();
        let signature = StandardInputSignature::new(signature.sighash_type(), raw_signature);
        tx_updater.witness[input] = InputWitness::Standard(signature);
        let tx = tx_updater.generate_tx().unwrap();

        assert!(matches!(
            verify_signature(chain_config, outpoint_dest, &tx, inputs_utxos, input),
            Err(DestinationSigError::SignatureVerificationFailed
                | DestinationSigError::InvalidSignatureEncoding)
        ));
    }
}

fn check_insert_output(
    chain_config: &ChainConfig,
    rng: &mut (impl Rng + CryptoRng),
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    destination: &Destination,
    should_fail: bool,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    tx_updater.outputs.push(TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1234567890)),
        Destination::PublicKey(pub_key),
    ));
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(chain_config, destination, &tx, inputs_utxos, 0);
    if should_fail {
        assert_eq!(res, Err(DestinationSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

fn add_value(output_value: OutputValue) -> OutputValue {
    match output_value {
        OutputValue::Coin(v) => OutputValue::Coin((v + Amount::from_atoms(100)).unwrap()),
        OutputValue::TokenV0(v) => OutputValue::TokenV0(v),
        OutputValue::TokenV1(d, v) => {
            OutputValue::TokenV1(d, (v + Amount::from_atoms(100)).unwrap())
        }
    }
}

fn check_mutate_output(
    chain_config: &ChainConfig,
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    destination: &Destination,
    should_fail: bool,
) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.outputs[0] = match tx_updater.outputs[0].clone() {
        TxOutput::Transfer(v, d) => TxOutput::Transfer(add_value(v), d),
        TxOutput::LockThenTransfer(v, d, l) => TxOutput::LockThenTransfer(add_value(v), d, l),
        TxOutput::Burn(v) => TxOutput::Burn(add_value(v)),
        TxOutput::Htlc(_, _) => todo!(),
        TxOutput::CreateStakePool(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::ProduceBlockFromStake(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::CreateDelegationId(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::DelegateStaking(_, _) => unreachable!(),
        TxOutput::IssueFungibleToken(_) => unreachable!(),
        TxOutput::IssueNft(_, _, _) => unreachable!(),
        TxOutput::DataDeposit(_) => unreachable!(),
    };

    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(chain_config, destination, &tx, inputs_utxos, 0);
    if should_fail {
        assert_eq!(res, Err(DestinationSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

fn check_mutate_input(
    chain_config: &ChainConfig,
    rng: &mut impl Rng,
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    destination: &Destination,
    should_fail: bool,
) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.inputs[0] = TxInput::from_utxo(
        OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random_using(rng))),
        9999,
    );
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(chain_config, destination, &tx, inputs_utxos, 0);
    if should_fail {
        assert_eq!(res, Err(DestinationSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

// An input UTXO mutation should result in signature verification error.
fn check_mutate_inputs_utxos(
    chain_config: &ChainConfig,
    original_tx: &SignedTransaction,
    inputs_utxos: &[Option<&TxOutput>],
    outpoint_dest: &Destination,
) {
    for input in 0..inputs_utxos.len() {
        let inputs_utxo = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(123456789012345)),
            Destination::AnyoneCanSpend,
        );
        let mut inputs_utxos = inputs_utxos.to_owned();
        inputs_utxos[input] = Some(&inputs_utxo);

        assert!(matches!(
            verify_signature(
                chain_config,
                outpoint_dest,
                original_tx,
                &inputs_utxos,
                input
            ),
            Err(DestinationSigError::SignatureVerificationFailed)
        ));
    }
}
