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

use crypto::key::SigAuxDataProvider;
use serialization::Encode;

use standard_signature::StandardInputSignature;

use crate::chain::{
    htlc::HtlcSecret, signature::sighash::input_commitments::SighashInputCommitment, ChainConfig,
    Destination, Transaction,
};

use super::{
    super::sighash::sighashtype::SigHashType,
    authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
    classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
    standard_signature, DestinationSigError, Signable,
};

#[allow(clippy::too_many_arguments)]
pub fn produce_uniparty_signature_for_htlc_spending<
    T: Signable,
    AuxP: SigAuxDataProvider + ?Sized,
>(
    private_key: &crypto::key::PrivateKey,
    sighash_type: SigHashType,
    outpoint_destination: Destination,
    tx: &T,
    input_commitments: &[SighashInputCommitment],
    input_num: usize,
    htlc_secret: HtlcSecret,
    sig_aux_data_provider: &mut AuxP,
) -> Result<StandardInputSignature, DestinationSigError> {
    let sig = StandardInputSignature::produce_uniparty_signature_for_input(
        private_key,
        sighash_type,
        outpoint_destination,
        tx,
        input_commitments,
        input_num,
        sig_aux_data_provider,
    )?;

    let sig_with_secret =
        AuthorizedHashedTimelockContractSpend::Spend(htlc_secret, sig.raw_signature().to_owned());
    let serialized_sig = sig_with_secret.encode();

    Ok(StandardInputSignature::new(
        sig.sighash_type(),
        serialized_sig,
    ))
}

pub fn produce_classical_multisig_signature_for_htlc_refunding(
    chain_config: &ChainConfig,
    authorization: &AuthorizedClassicalMultisigSpend,
    sighash_type: SigHashType,
    tx: &Transaction,
    input_commitments: &[SighashInputCommitment],
    input_num: usize,
) -> Result<StandardInputSignature, DestinationSigError> {
    let sig = StandardInputSignature::produce_classical_multisig_signature_for_input(
        chain_config,
        authorization,
        sighash_type,
        tx,
        input_commitments,
        input_num,
    )?;

    let raw_signature =
        AuthorizedHashedTimelockContractSpend::Refund(sig.raw_signature().to_owned()).encode();

    Ok(StandardInputSignature::new(
        sig.sighash_type(),
        raw_signature,
    ))
}

pub fn produce_uniparty_signature_for_htlc_refunding<
    T: Signable,
    AuxP: SigAuxDataProvider + ?Sized,
>(
    private_key: &crypto::key::PrivateKey,
    sighash_type: SigHashType,
    outpoint_destination: Destination,
    tx: &T,
    input_commitments: &[SighashInputCommitment],
    input_num: usize,
    sig_aux_data_provider: &mut AuxP,
) -> Result<StandardInputSignature, DestinationSigError> {
    let sig = StandardInputSignature::produce_uniparty_signature_for_input(
        private_key,
        sighash_type,
        outpoint_destination,
        tx,
        input_commitments,
        input_num,
        sig_aux_data_provider,
    )?;

    let sig_with_secret =
        AuthorizedHashedTimelockContractSpend::Refund(sig.raw_signature().to_owned());
    let serialized_sig = sig_with_secret.encode();

    Ok(StandardInputSignature::new(
        sig.sighash_type(),
        serialized_sig,
    ))
}
