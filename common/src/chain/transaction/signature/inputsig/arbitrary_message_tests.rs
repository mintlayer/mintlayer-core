// Copyright (c) 2021-2024 RBB S.r.l
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

use rstest::rstest;

use chain::signature::{
    inputsig::{standard_signature::StandardInputSignature, InputWitness},
    sighash::{sighashtype::SigHashType, signature_hash},
    tests::utils::{generate_input_utxo, generate_unsigned_tx},
    verify_signature, SignedTransaction,
};
use crypto::{
    hash::StreamHasher,
    key::{KeyKind, PrivateKey},
    random::Rng,
};
use test_utils::{
    assert_matches,
    random::{flip_random_bit, with_random_bit_flipped, Seed},
};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{self, Destination},
    primitives::{id::DefaultHashAlgoStream, Id},
};

use super::*;

// Sign and verify a message using supported destinations.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_verify_supported_destinations(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let destination_addr = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let destination_pub_key = Destination::PublicKey(public_key);

    for dest in [&destination_addr, &destination_pub_key] {
        let sig = SignedArbitraryMessage::produce_uniparty_signature(&private_key, dest, &message)
            .unwrap();
        let ver_result = sig.verify_signature(&chain_config, dest, &message_challenge);
        assert_eq!(ver_result, Ok(()));
    }
}

// Try to sign and verify using a destination that is unsupported for signing and/or verification.
// Specific errors should be produced in each case.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_verify_unsupported_destination(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let random_raw_sig: Vec<u8> = (1..100).map(|_| rng.gen()).collect();
    let random_sig = SignedArbitraryMessage {
        raw_signature: random_raw_sig,
    };

    // Destination::ClassicMultisig can't be used by produce_uniparty_signature.
    let destination = Destination::ClassicMultisig(PublicKeyHash::from(&public_key));
    let sig_err =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap_err();
    assert_eq!(
        sig_err,
        SignArbitraryMessageError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode
    );

    // Destination::ScriptHash is unsupported
    let destination = Destination::ScriptHash(Id::<_>::new(H256::random_using(&mut rng)));
    let sig_err =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap_err();
    assert_eq!(sig_err, SignArbitraryMessageError::Unsupported);
    // Verifying a random signature should also produce an "Unsupported" error.
    let ver_err = random_sig
        .verify_signature(&chain_config, &destination, &message_challenge)
        .unwrap_err();
    assert_eq!(ver_err, DestinationSigError::Unsupported);

    // Destination::AnyoneCanSpend makes no sense for this functionality.
    let destination = Destination::AnyoneCanSpend;
    let sig_err =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap_err();
    assert_eq!(
        sig_err,
        SignArbitraryMessageError::AttemptedToProduceSignatureForAnyoneCanSpend
    );
    // Verifying a random signature should also produce an "Unsupported" error.
    let ver_err = random_sig
        .verify_signature(&chain_config, &destination, &message_challenge)
        .unwrap_err();
    assert_eq!(
        ver_err,
        DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend
    );
}

// Sign a message using one of the supported destinations, but use a different one for verification.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_wrong_destination(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (_, public_key2) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let dest_multisig = Destination::ClassicMultisig(PublicKeyHash::from(&public_key));
    let dest_scripthash = Destination::ScriptHash(Id::<_>::new(H256::random_using(&mut rng)));
    let dest_addr = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let dest_addr2 = Destination::PublicKeyHash(PublicKeyHash::from(&public_key2));
    let dest_pub_key = Destination::PublicKey(public_key);
    let dest_pub_key2 = Destination::PublicKey(public_key2);

    let assert_result = |expected_res| move |res| assert_eq!(res, expected_res);

    #[allow(clippy::type_complexity)]
    let test_data: &[(
        &Destination,
        &Destination,
        &dyn Fn(Result<(), DestinationSigError>),
    )] = &[
        (
            &dest_addr,
            &dest_addr2,
            &assert_result(Err(DestinationSigError::PublicKeyToAddressMismatch)),
        ),
        (
            &dest_addr,
            &dest_pub_key,
            &assert_result(Err(DestinationSigError::InvalidSignatureEncoding)),
        ),
        (
            &dest_addr,
            &dest_multisig,
            &assert_result(Err(DestinationSigError::InvalidSignatureEncoding)),
        ),
        (
            &dest_addr,
            &dest_scripthash,
            &assert_result(Err(DestinationSigError::Unsupported)),
        ),
        (
            &dest_addr,
            &Destination::AnyoneCanSpend,
            &assert_result(Err(
                DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
            )),
        ),
        (
            &dest_pub_key,
            &dest_pub_key2,
            &assert_result(Err(DestinationSigError::SignatureVerificationFailed)),
        ),
        (&dest_pub_key, &dest_addr, &|res| {
            assert_matches!(res, Err(DestinationSigError::AddressAuthDecodingFailed(_)))
        }),
        (
            &dest_pub_key,
            &dest_multisig,
            &assert_result(Err(DestinationSigError::InvalidSignatureEncoding)),
        ),
        (
            &dest_pub_key,
            &dest_scripthash,
            &assert_result(Err(DestinationSigError::Unsupported)),
        ),
        (
            &dest_pub_key,
            &Destination::AnyoneCanSpend,
            &assert_result(Err(
                DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
            )),
        ),
    ];

    for (sign_dest, verify_dest, check_func) in test_data {
        let sig =
            SignedArbitraryMessage::produce_uniparty_signature(&private_key, sign_dest, &message)
                .unwrap();
        let ver_result = sig.verify_signature(&chain_config, verify_dest, &message_challenge);
        check_func(ver_result);
    }
}

// Sign a message using a supported destination and use it to verify a corrupted message
// (one bit of which was flipped). The verification should fail.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_corrupted_message(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();

    let corrupted_message = with_random_bit_flipped(&message, &mut rng);
    let corrupted_message_challenge = produce_message_challenge(&corrupted_message);

    let destination_addr = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let destination_pub_key = Destination::PublicKey(public_key);

    for dest in [&destination_addr, &destination_pub_key] {
        let sig = SignedArbitraryMessage::produce_uniparty_signature(&private_key, dest, &message)
            .unwrap();
        let ver_result = sig.verify_signature(&chain_config, dest, &corrupted_message_challenge);
        assert_eq!(
            ver_result,
            Err(DestinationSigError::SignatureVerificationFailed)
        );
    }
}

// Sign a message using a supported destination and corrupt the signature by flipping one of
// its bits. The verification should fail.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn verify_corrupted_signature(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let destination_addr = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let destination_pub_key = Destination::PublicKey(public_key);

    for dest in [&destination_addr, &destination_pub_key] {
        let mut sig =
            SignedArbitraryMessage::produce_uniparty_signature(&private_key, dest, &message)
                .unwrap();
        flip_random_bit(&mut sig.raw_signature, &mut rng);

        let ver_result = sig.verify_signature(&chain_config, dest, &message_challenge);
        // The actual error will depend on which bit gets flipped.
        assert!(ver_result.is_err());
    }
}

// A test that checks that SignedArbitraryMessage can't be used to sign a transaction.
// 1) Construct a message containing tx data that would normally be hashed when signing
// a transaction.
// 2) As a sanity check, hash the message and use one of the "standard" functions
// (sign_pubkey_spending) to produce a tx signature; check that the signature is indeed correct.
// 3) Sign the message via SignedArbitraryMessage::produce_uniparty_signature; check that the
// result is NOT a valid transaction signature.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signing_transactions_shouldnt_work(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (input_utxo, _) = generate_input_utxo(&mut rng);
    let destination = Destination::PublicKey(public_key.clone());
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();

    let tx = generate_unsigned_tx(
        &mut rng,
        &Destination::AnyoneCanSpend,
        &[Some(input_utxo.clone())],
        1,
    )
    .unwrap();

    let unhashed_tx_data_to_sign = {
        let mut data = Vec::<u8>::new();
        sighash_type.get().encode_to(&mut data);
        tx.version_byte().encode_to(&mut data);
        tx.flags().encode_to(&mut data);
        tx.inputs()[0].encode_to(&mut data);
        Some(&input_utxo).encode_to(&mut data);
        data
    };

    let tx_data_hash: H256 = {
        let mut stream = DefaultHashAlgoStream::new();
        stream.write(&unhashed_tx_data_to_sign);
        stream.finalize().into()
    };

    // Sanity check - if we sign tx_data_hash normally, it will actually produce a correct
    // transaction signature.
    {
        let expected_hash = signature_hash(sighash_type, &tx, &[Some(&input_utxo)], 0).unwrap();
        assert_eq!(tx_data_hash, expected_hash);

        let raw_sig =
            sign_pubkey_spending(&private_key, &public_key, &tx_data_hash).unwrap().encode();

        let sig = StandardInputSignature::new(sighash_type, raw_sig);
        let signed_tx =
            SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(sig)]).unwrap();

        verify_signature(
            &chain_config,
            &destination,
            &signed_tx,
            &[Some(&input_utxo)],
            0,
        )
        .unwrap();
    }

    // Now try the "arbitrary message" signature.
    let msg_sig = SignedArbitraryMessage::produce_uniparty_signature(
        &private_key,
        &destination,
        &unhashed_tx_data_to_sign,
    )
    .unwrap();
    // Sanity check - ensure that the signature itself is correct.
    let msg_challenge = produce_message_challenge(&unhashed_tx_data_to_sign);
    msg_sig.verify_signature(&chain_config, &destination, &msg_challenge).unwrap();

    // Now try to use it as a "transaction signature" - the verification should fail.
    let sig = StandardInputSignature::new(sighash_type, msg_sig.raw_signature);
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::Standard(sig)]).unwrap();

    let ver_err = verify_signature(
        &chain_config,
        &destination,
        &signed_tx,
        &[Some(&input_utxo)],
        0,
    )
    .unwrap_err();
    assert_eq!(ver_err, DestinationSigError::SignatureVerificationFailed);
}
