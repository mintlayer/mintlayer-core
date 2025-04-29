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

use std::{
    collections::BTreeMap,
    num::{NonZeroU8, NonZeroUsize},
};

use crypto::key::{PrivateKey, PublicKey, Signature};
use serialization::Encode;

use crate::chain::{
    classic_multisig::ClassicMultisigChallenge,
    signature::{
        inputsig::{
            authorize_pubkey_spend::AuthorizedPublicKeySpend,
            authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
            classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
            standard_signature::StandardInputSignature, InputWitness,
        },
        sighash::sighashtype::SigHashType,
    },
    Destination, SignedTransaction, Transaction, TxOutput,
};

/// Wallet errors
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SizeEstimationError {
    #[error("Unsupported input destination")]
    UnsupportedInputDestination(Destination),
}

/// Return the encoded size of an input signature.
///
/// ScriptHash destinations are not supported. ClassicMultisig destinations are only supported
/// if dest_info_provider is not None and it is able to return MultisigInfo for the
/// provided destination.
pub fn input_signature_size(
    txo: &TxOutput,
    dest_info_provider: Option<&dyn DestinationInfoProvider>,
) -> Result<usize, SizeEstimationError> {
    get_tx_output_destination(txo).map_or(Ok(0), |dest| {
        input_signature_size_from_destination(dest, dest_info_provider)
    })
}

lazy_static::lazy_static! {
    static ref BOGUS_KEY_PAIR_AND_SIGNATURE: (PrivateKey, PublicKey, Signature) = {
        let (private_key, public_key) =
            PrivateKey::new_from_entropy(crypto::key::KeyKind::Secp256k1Schnorr);
        let signature = private_key
            .sign_message(&[0; 32], randomness::make_true_rng())
            .expect("should not fail");
        (private_key, public_key, signature)
    };
}

mod multisig_signature_size_impl {
    use std::sync::Mutex;

    use super::*;

    // Cache results of multisig_signature_size, because it's relatively expensive.
    static CACHE: Mutex<BTreeMap<MultisigInfo, usize>> = Mutex::new(BTreeMap::new());

    pub fn multisig_signature_size(info: MultisigInfo) -> usize {
        use std::collections::btree_map::Entry;

        match CACHE.lock().expect("poisoned mutex").entry(info) {
            Entry::Vacant(entry) => {
                let signatures = (0..info.min_required_signatures.get())
                    .map(|i| (i, BOGUS_KEY_PAIR_AND_SIGNATURE.2.clone()))
                    .collect::<BTreeMap<_, _>>();
                let challenge = ClassicMultisigChallenge::new_unchecked(
                    info.min_required_signatures,
                    vec![BOGUS_KEY_PAIR_AND_SIGNATURE.1.clone(); info.total_keys.get()],
                );

                let raw_signature =
                    AuthorizedClassicalMultisigSpend::new(signatures, challenge).encode();

                let standard = StandardInputSignature::new(SigHashType::all(), raw_signature);
                let size = InputWitness::Standard(standard).encoded_size();
                *entry.insert(size)
            }
            Entry::Occupied(entry) => *entry.get(),
        }
    }
}
use multisig_signature_size_impl::multisig_signature_size;

lazy_static::lazy_static! {
    static ref NO_SIGNATURE_SIZE: usize = {
        InputWitness::NoSignature(None).encoded_size()
    };
}

lazy_static::lazy_static! {
    static ref PUB_KEY_SIGNATURE_SIZE: usize = {
        let raw_signature =
            AuthorizedPublicKeySpend::new(BOGUS_KEY_PAIR_AND_SIGNATURE.2.clone()).encode();
        let standard = StandardInputSignature::new(
            SigHashType::all(),
            raw_signature,
        );
        InputWitness::Standard(standard).encoded_size()
    };
}

lazy_static::lazy_static! {
    static ref ADDRESS_SIGNATURE_SIZE: usize = {
        let raw_signature = AuthorizedPublicKeyHashSpend::new(
            BOGUS_KEY_PAIR_AND_SIGNATURE.1.clone(),
            BOGUS_KEY_PAIR_AND_SIGNATURE.2.clone(),
        )
        .encode();
        let standard = StandardInputSignature::new(
            SigHashType::all(),
            raw_signature,
        );
        InputWitness::Standard(standard).encoded_size()
    };
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct MultisigInfo {
    total_keys: NonZeroUsize,
    min_required_signatures: NonZeroU8,
}

impl MultisigInfo {
    pub fn new(total_keys: NonZeroUsize, min_required_signatures: NonZeroU8) -> Self {
        Self {
            total_keys,
            min_required_signatures,
        }
    }

    pub fn from_challenge(challenge: &ClassicMultisigChallenge) -> Self {
        Self {
            total_keys: challenge.public_keys_count_as_non_zero(),
            min_required_signatures: challenge.min_required_signatures_as_non_zero(),
        }
    }

    pub fn total_keys(&self) -> NonZeroUsize {
        self.total_keys
    }

    pub fn min_required_signatures(&self) -> NonZeroU8 {
        self.min_required_signatures
    }
}

pub trait DestinationInfoProvider {
    fn get_multisig_info(&self, destination: &Destination) -> Option<MultisigInfo>;
}

/// Return the encoded size of an input signature.
///
/// ScriptHash destinations are not supported. ClassicMultisig destinations are only supported
/// if dest_info_provider is not None and it is able to return MultisigInfo for the
/// provided destination.
pub fn input_signature_size_from_destination(
    destination: &Destination,
    dest_info_provider: Option<&dyn DestinationInfoProvider>,
) -> Result<usize, SizeEstimationError> {
    // Sizes calculated upfront
    match destination {
        Destination::PublicKeyHash(_) => Ok(*ADDRESS_SIGNATURE_SIZE),
        Destination::PublicKey(_) => Ok(*PUB_KEY_SIGNATURE_SIZE),
        Destination::AnyoneCanSpend => Ok(*NO_SIGNATURE_SIZE),
        Destination::ScriptHash(_) => Err(SizeEstimationError::UnsupportedInputDestination(
            destination.clone(),
        )),
        Destination::ClassicMultisig(_) => dest_info_provider
            .and_then(|dest_info_provider| dest_info_provider.get_multisig_info(destination))
            .map(multisig_signature_size)
            .ok_or_else(|| SizeEstimationError::UnsupportedInputDestination(destination.clone())),
    }
}

/// Return the encoded size for a SignedTransaction with specified outputs and empty inputs and
/// signatures
pub fn tx_size_with_outputs(outputs: &[TxOutput], num_inputs: usize) -> usize {
    #[derive(Encode)]
    struct CompactSize {
        #[codec(compact)]
        value: u64,
    }

    let tx = SignedTransaction::new(
        Transaction::new(1, vec![], outputs.into()).expect("should not fail"),
        vec![],
    )
    .expect("should not fail");
    let size = serialization::Encode::encoded_size(&tx);

    let compact_size_diff = serialization::Encode::encoded_size(&CompactSize {
        value: num_inputs as u64,
    }) - serialization::Encode::encoded_size(&CompactSize { value: 0 });

    size + (compact_size_diff * 2) // 2 for number of inputs and number of input signatures
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
