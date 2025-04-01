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

use randomness::{CryptoRng, Rng};
use serialization::Encode;

use standard_signature::StandardInputSignature;

use crate::chain::{
    htlc::HtlcSecret, signature::sighash::SighashInputInfo, ChainConfig, Destination, Transaction,
};

use super::{
    super::sighash::sighashtype::SigHashType,
    authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
    classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
    standard_signature, DestinationSigError, Signable,
};

#[allow(clippy::too_many_arguments)]
pub fn produce_uniparty_signature_for_htlc_input<T: Signable, R: Rng + CryptoRng>(
    private_key: &crypto::key::PrivateKey,
    sighash_type: SigHashType,
    outpoint_destination: Destination,
    tx: &T,
    inputs_info: &[SighashInputInfo],
    input_num: usize,
    htlc_secret: HtlcSecret,
    rng: R,
) -> Result<StandardInputSignature, DestinationSigError> {
    let sig = StandardInputSignature::produce_uniparty_signature_for_input(
        private_key,
        sighash_type,
        outpoint_destination,
        tx,
        inputs_info,
        input_num,
        rng,
    )?;

    let sig_with_secret =
        AuthorizedHashedTimelockContractSpend::Secret(htlc_secret, sig.raw_signature().to_owned());
    let serialized_sig = sig_with_secret.encode();

    Ok(StandardInputSignature::new(
        sig.sighash_type(),
        serialized_sig,
    ))
}

pub fn produce_classical_multisig_signature_for_htlc_input(
    chain_config: &ChainConfig,
    authorization: &AuthorizedClassicalMultisigSpend,
    sighash_type: SigHashType,
    tx: &Transaction,
    inputs_info: &[SighashInputInfo],
    input_num: usize,
) -> Result<StandardInputSignature, DestinationSigError> {
    let sig = StandardInputSignature::produce_classical_multisig_signature_for_input(
        chain_config,
        authorization,
        sighash_type,
        tx,
        inputs_info,
        input_num,
    )?;

    let raw_signature =
        AuthorizedHashedTimelockContractSpend::Multisig(sig.raw_signature().to_owned()).encode();

    Ok(StandardInputSignature::new(
        sig.sighash_type(),
        raw_signature,
    ))
}
