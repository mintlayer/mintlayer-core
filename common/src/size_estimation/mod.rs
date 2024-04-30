// Copyright (c) 2021-2022 RBB S.r.l
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

use crypto::key::PrivateKey;
use serialization::Encode;

use crate::chain::{
    signature::{
        inputsig::{
            authorize_pubkey_spend::AuthorizedPublicKeySpend,
            authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
            standard_signature::StandardInputSignature, InputWitness,
        },
        sighash::sighashtype::SigHashType,
    },
    Destination, SignedTransaction, Transaction, TxOutput,
};

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SizeEstimationError {
    #[error("Unsupported input destination")]
    UnsupportedInputDestination(Destination),
}

/// Return the encoded size of an input signature
pub fn input_signature_size(txo: &TxOutput) -> Result<usize, SizeEstimationError> {
    get_tx_output_destination(txo).map_or(Ok(0), input_signature_size_from_destination)
}

fn no_signature_size() -> usize {
    InputWitness::NoSignature(None).encoded_size()
}

fn public_key_signature_size() -> usize {
    let (private_key, _) = PrivateKey::new_from_entropy(crypto::key::KeyKind::Secp256k1Schnorr);
    let signature = private_key
        .sign_message(&[0; 32], randomness::make_true_rng())
        .expect("should not fail");
    let raw_signature = AuthorizedPublicKeySpend::new(signature).encode();
    let standard = StandardInputSignature::new(
        SigHashType::try_from(SigHashType::ALL).expect("should not fail"),
        raw_signature,
    );
    InputWitness::Standard(standard).encoded_size()
}

fn address_signature_size() -> usize {
    let (private_key, public_key) =
        PrivateKey::new_from_entropy(crypto::key::KeyKind::Secp256k1Schnorr);
    let signature = private_key
        .sign_message(&[0; 32], randomness::make_true_rng())
        .expect("should not fail");
    let raw_signature = AuthorizedPublicKeyHashSpend::new(public_key, signature).encode();
    let standard = StandardInputSignature::new(
        SigHashType::try_from(SigHashType::ALL).expect("should not fail"),
        raw_signature,
    );
    InputWitness::Standard(standard).encoded_size()
}

/// Return the encoded size of an input signature
pub fn input_signature_size_from_destination(
    destination: &Destination,
) -> Result<usize, SizeEstimationError> {
    // Sizes calculated upfront
    match destination {
        Destination::PublicKeyHash(_) => Ok(address_signature_size()),
        Destination::PublicKey(_) => Ok(public_key_signature_size()),
        Destination::AnyoneCanSpend => Ok(no_signature_size()),
        Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => Err(
            SizeEstimationError::UnsupportedInputDestination(destination.clone()),
        ),
    }
}

/// Return the encoded size for a SignedTransaction with specified outputs and empty inputs and
/// signatures
pub fn tx_size_with_outputs(outputs: &[TxOutput]) -> usize {
    let tx = SignedTransaction::new(
        Transaction::new(1, vec![], outputs.into()).expect("should not fail"),
        vec![],
    )
    .expect("should not fail");
    serialization::Encode::encoded_size(&tx)
}

fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
    match txo {
        TxOutput::Transfer(_, d)
        | TxOutput::LockThenTransfer(_, d, _)
        | TxOutput::CreateDelegationId(d, _)
        | TxOutput::IssueNft(_, _, d)
        | TxOutput::ProduceBlockFromStake(d, _) => Some(d),
        TxOutput::CreateStakePool(_, data) => Some(data.staker()),
        TxOutput::Htlc(_, htlc) => Some(&htlc.spend_key),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
    }
}
