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
};
use crypto::{
    hash::StreamHasher,
    key::{KeyKind, PrivateKey, PublicKey},
};
use randomness::Rng;
use serialization::DecodeAll;
use test_utils::{
    assert_matches,
    random::{flip_random_bit, with_random_bit_flipped, Seed},
};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{self, Destination, SignedTransaction},
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
        let sig = ArbitraryMessageSignature::produce_uniparty_signature(
            &private_key,
            dest,
            &message,
            &mut rng,
        )
        .unwrap();
        let ver_result = sig.verify_signature(&chain_config, dest, &message_challenge);
        assert_eq!(ver_result, Ok(()));
    }
}

// Check that `produce_uniparty_signature_as_pub_key_hash_spending` gives the same result as
// `produce_uniparty_signature` does for `Destination::PublicKeyHash`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn produce_uniparty_signature_as_pub_key_hash_spending_matches_produce_uniparty_signature(
    #[case] seed: Seed,
) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let destination_addr = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    // Use the identical rng for both of the signer calls to be able to compare the signatures.
    let signer_rng_seed = rng.gen();

    let sig1 = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination_addr,
        &message,
        test_utils::random::make_seedable_rng(signer_rng_seed),
    )
    .unwrap();
    sig1.verify_signature(&chain_config, &destination_addr, &message_challenge)
        .unwrap();

    let sig2 = ArbitraryMessageSignature::produce_uniparty_signature_as_pub_key_hash_spending(
        &private_key,
        &message,
        test_utils::random::make_seedable_rng(signer_rng_seed),
    )
    .unwrap();

    assert_eq!(sig1, sig2);
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
    let random_sig = ArbitraryMessageSignature {
        raw_signature: random_raw_sig,
    };

    // Destination::ClassicMultisig can't be used by produce_uniparty_signature.
    let destination = Destination::ClassicMultisig(PublicKeyHash::from(&public_key));
    let sig_err = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination,
        &message,
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(
        sig_err,
        SignArbitraryMessageError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode
    );

    // Destination::ScriptHash is unsupported
    let destination = Destination::ScriptHash(Id::<_>::new(H256::random_using(&mut rng)));
    let sig_err = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination,
        &message,
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(sig_err, SignArbitraryMessageError::Unsupported);
    // Verifying a random signature should also produce an "Unsupported" error.
    let ver_err = random_sig
        .verify_signature(&chain_config, &destination, &message_challenge)
        .unwrap_err();
    assert_eq!(ver_err, DestinationSigError::Unsupported);

    // Destination::AnyoneCanSpend makes no sense for this functionality.
    let destination = Destination::AnyoneCanSpend;
    let sig_err = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination,
        &message,
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(
        sig_err,
        SignArbitraryMessageError::AttemptedToProduceSignatureForAnyoneCanSpend
    );
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
            &assert_result(Err(DestinationSigError::PublicKeyToHashMismatch)),
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
        let sig = ArbitraryMessageSignature::produce_uniparty_signature(
            &private_key,
            sign_dest,
            &message,
            &mut rng,
        )
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
        let sig = ArbitraryMessageSignature::produce_uniparty_signature(
            &private_key,
            dest,
            &message,
            &mut rng,
        )
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
        let mut sig = ArbitraryMessageSignature::produce_uniparty_signature(
            &private_key,
            dest,
            &message,
            &mut rng,
        )
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
// (sign_public_key_spending) to produce a tx signature; check that the signature is indeed correct.
// 3) Sign the message via SignedArbitraryMessage::produce_uniparty_signature; check that the
// result is NOT a valid transaction signature.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signing_transactions_shouldnt_work(#[case] seed: Seed) {
    use crate::chain::signature::tests::utils::verify_signature;

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

        let raw_sig = sign_public_key_spending(&private_key, &public_key, &tx_data_hash, &mut rng)
            .unwrap()
            .encode();

        let sig = StandardInputSignature::new(sighash_type, raw_sig);
        let signed_tx =
            SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(sig)]).unwrap();

        verify_signature(
            &chain_config,
            &destination,
            &signed_tx,
            &signed_tx.signatures()[0],
            &[Some(&input_utxo)],
            0,
        )
        .unwrap();
    }

    // Now try the "arbitrary message" signature.
    let msg_sig = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination,
        &unhashed_tx_data_to_sign,
        &mut rng,
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
        &signed_tx.signatures()[0],
        &[Some(&input_utxo)],
        0,
    )
    .unwrap_err();
    assert_eq!(ver_err, DestinationSigError::SignatureVerificationFailed);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signature_with_chosen_text(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let private_key_hex = "0085b02139ad6f21099f842d4cf6af705bb8927b9589835be1fef5f53e74e360f3";
    let private_key_bytes = hex::decode(private_key_hex).unwrap();
    let private_key = PrivateKey::decode_all(&mut private_key_bytes.as_slice()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);

    let chain_config = chain::config::create_testnet();

    let message =
        "Lorem Ipsum is simply dummy text of the printing and typesetting industry.".as_bytes();
    let message_challenge = produce_message_challenge(message);

    // Ensure the challenge format hasn't changed
    let message_challenge_hex = "aa0fa46ccf0a2280611faf94ea4f69594859d88e26c460a422dea4b66cc2f927";
    let message_challenge_bytes = hex::decode(message_challenge_hex).unwrap();
    let message_challenge_reproduced =
        H256::decode_all(&mut message_challenge_bytes.as_slice()).unwrap();
    assert_eq!(message_challenge_reproduced, message_challenge);

    let destination_pubkeyhash = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));
    let destination_pub_key = Destination::PublicKey(public_key);

    ////////////////////////////////////////////////////////////
    // Public key hash verification
    ////////////////////////////////////////////////////////////
    let signature_pubkeyhash = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination_pubkeyhash,
        message,
        &mut rng,
    )
    .unwrap();

    ArbitraryMessageSignature::from_data(signature_pubkeyhash.raw_signature)
        .verify_signature(&chain_config, &destination_pubkeyhash, &message_challenge)
        .unwrap();

    // Ensure the stored signature will always verify correctly
    let signature_pubkeyhash_hex = "00030b84796d1e4f528dc7469c03beda6d9158126818ecf0df28e86354246d3de84900fa947e4e502cfa7d608fca02e826606b3c59e20dd14e2694f14152b2947d683cf2ab8df603c57f9706d87fe81fded47f73727ce316ec33cac01da96791f10dfc";
    let signature_pubkeyhash_bytes = hex::decode(signature_pubkeyhash_hex).unwrap();
    ArbitraryMessageSignature::from_data(signature_pubkeyhash_bytes)
        .verify_signature(&chain_config, &destination_pubkeyhash, &message_challenge)
        .unwrap();
    ////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////
    // Public key verification
    ////////////////////////////////////////////////////////////
    let signature_pub_key = ArbitraryMessageSignature::produce_uniparty_signature(
        &private_key,
        &destination_pub_key,
        message,
        &mut rng,
    )
    .unwrap();
    ArbitraryMessageSignature::from_data(signature_pub_key.raw_signature)
        .verify_signature(&chain_config, &destination_pub_key, &message_challenge)
        .unwrap();

    // Ensure the stored signature will always verify correctly
    let signature_pubkey_hex = "004cf0b83576b35b6684eebcad34b1900d4176d844753665fdf7c042e8cc71d6cfe8a4f9f5c24adfbe8a16e3dead56ea07e2deca4b7bffb1376f04205d6dedbc6e";
    let signature_pubkey_bytes = hex::decode(signature_pubkey_hex).unwrap();
    ArbitraryMessageSignature::from_data(signature_pubkey_bytes)
        .verify_signature(&chain_config, &destination_pub_key, &message_challenge)
        .unwrap();
    ////////////////////////////////////////////////////////////
}
