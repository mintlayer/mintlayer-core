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

use common::chain::{
    signature::{
        inputsig::{
            htlc::produce_uniparty_signature_for_htlc_input,
            standard_signature::StandardInputSignature, InputWitness,
        },
        sighash::{input_commitments::SighashInputCommitment, sighashtype::SigHashType},
    },
    Destination, TxOutput,
};
use crypto::key::{PrivateKey, SigAuxDataProvider};
use wallet_types::partially_signed_transaction::PartiallySignedTransaction;

use crate::signer::{SignerError, SignerResult};

pub fn sign_input_with_standalone_key<AuxP: SigAuxDataProvider + ?Sized>(
    secret: &Option<common::chain::htlc::HtlcSecret>,
    standalone_pk: &PrivateKey,
    destination: &Destination,
    ptx: &PartiallySignedTransaction,
    input_commitments: &[SighashInputCommitment],
    input_index: usize,
    sig_aux_data_provider: &mut AuxP,
) -> SignerResult<InputWitness> {
    let sighash_type = SigHashType::all();
    match secret {
        Some(htlc_secret) => produce_uniparty_signature_for_htlc_input(
            standalone_pk,
            sighash_type,
            destination.clone(),
            ptx.tx(),
            input_commitments,
            input_index,
            htlc_secret.clone(),
            sig_aux_data_provider,
        ),
        None => StandardInputSignature::produce_uniparty_signature_for_input(
            standalone_pk,
            sighash_type,
            destination.clone(),
            ptx.tx(),
            input_commitments,
            input_index,
            sig_aux_data_provider,
        ),
    }
    .map(InputWitness::Standard)
    .map_err(SignerError::SigningError)
}

pub fn is_htlc_utxo(utxo: &TxOutput) -> bool {
    match utxo {
        TxOutput::Htlc(_, _) => true,

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
    }
}
