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
use test_utils::random::Seed;

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{self, Destination},
    primitives::{id::DefaultHashAlgoStream, Id},
};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_verify(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = chain::config::create_testnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let message: Vec<u8> = (20..40).map(|_| rng.gen()).collect();
    let message_challenge = produce_message_challenge(&message);

    let random_raw_sig: Vec<u8> = (1..100).map(|_| rng.gen()).collect();
    let random_sig = SignedArbitraryMessage {
        raw_signature: random_raw_sig,
    };

    // Destination::Address
    let destination = Destination::Address(PublicKeyHash::from(&public_key));
    let sig =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap();
    sig.verify_signature(&chain_config, &destination, &message_challenge).unwrap();

    // Destination::PublicKey
    let destination = Destination::PublicKey(public_key.clone());
    let sig =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap();
    sig.verify_signature(&chain_config, &destination, &message_challenge).unwrap();

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

    // Destination::AnyoneCanSpend makes no sense for this functionality and should produce
    // a specific error.
    let destination = Destination::AnyoneCanSpend;
    let sig_err =
        SignedArbitraryMessage::produce_uniparty_signature(&private_key, &destination, &message)
            .unwrap_err();
    assert_eq!(
        sig_err,
        SignArbitraryMessageError::AttemptedToProduceSignatureForAnyoneCanSpend
    );
    // Same for the verification.
    let ver_err = random_sig
        .verify_signature(&chain_config, &destination, &message_challenge)
        .unwrap_err();
    assert_eq!(
        ver_err,
        DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend
    );
}

// Basic test that checks that SignedArbitraryMessage can't be used to sign a transaction.
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

    let raw_sig = SignedArbitraryMessage::produce_uniparty_signature(
        &private_key,
        &destination,
        &unhashed_tx_data_to_sign,
    )
    .unwrap()
    .raw_signature;

    let sig = StandardInputSignature::new(sighash_type, raw_sig);
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
