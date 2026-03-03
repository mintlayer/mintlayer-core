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

use serialization::Encode;

use crate::chain::{
    signature::{
        inputsig::{
            authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
            standard_signature::StandardInputSignature,
        },
        sighash::sighashtype::SigHashType,
        DestinationSigError,
    },
    TxOutput,
};

use super::authorize_classical_multisig::AuthorizedClassicalMultisigSpend;

pub fn encode_multisig_spend(
    sig_component: &AuthorizedClassicalMultisigSpend,
    utxo: Option<&TxOutput>,
) -> StandardInputSignature {
    let raw_signature = match utxo {
        Some(utxo) => {
            if is_htlc_output(utxo) {
                AuthorizedHashedTimelockContractSpend::Refund(sig_component.encode()).encode()
            } else {
                sig_component.encode()
            }
        }
        None => sig_component.encode(),
    };

    let sighash_type = SigHashType::all();
    StandardInputSignature::new(sighash_type, raw_signature)
}

pub fn decode_multisig_spend(
    sig: &StandardInputSignature,
    utxo: Option<&TxOutput>,
) -> Result<AuthorizedClassicalMultisigSpend, DestinationSigError> {
    let sig_component = match utxo {
        Some(utxo) => {
            if is_htlc_output(utxo) {
                let htlc_spend =
                    AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())?;
                match htlc_spend {
                    AuthorizedHashedTimelockContractSpend::Spend(_, _) => {
                        return Err(DestinationSigError::InvalidClassicalMultisigAuthorization);
                    }
                    AuthorizedHashedTimelockContractSpend::Refund(raw_signature) => {
                        AuthorizedClassicalMultisigSpend::from_data(&raw_signature)?
                    }
                }
            } else {
                AuthorizedClassicalMultisigSpend::from_data(sig.raw_signature())?
            }
        }
        None => AuthorizedClassicalMultisigSpend::from_data(sig.raw_signature())?,
    };
    Ok(sig_component)
}

fn is_htlc_output(output: &TxOutput) -> bool {
    match output {
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
        TxOutput::Htlc(_, _) => true,
    }
}
