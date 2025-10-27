// Copyright (c) 2021-2025 RBB S.r.l
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

//! Some internal functions are defined here, used mainly for testing.

use wasm_bindgen::prelude::*;

use common::{
    chain::{
        config::Builder,
        partially_signed_transaction::make_sighash_input_commitments_at_height,
        signature::{
            inputsig::{
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::signature_hash,
        },
        Transaction, TxOutput,
    },
    primitives::BlockHeight,
};
use serialization::DecodeAll;
use utils::ensure;

use crate::{
    error::Error,
    types::{Network, SignatureHashType, TxAdditionalInfo},
    utils::{decode_raw_array, extract_htlc_spend, parse_addressable, to_ptx_additional_info},
};

/// Verify a witness produced by one of the `encode_witness` functions.
///
/// `input_owner_destination` must be specified if `witness` actually contains a signature
/// (i.e. it's not InputWitness::NoSignature) and the input is not an HTLC one. Otherwise it must
/// be null.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn internal_verify_witness(
    sighashtype: SignatureHashType,
    input_owner_destination: Option<String>,
    witness: &[u8],
    transaction: &[u8],
    input_utxos: &[u8],
    input_index: u32,
    additional_info: TxAdditionalInfo,
    current_block_height: u64,
    network: Network,
) -> Result<(), Error> {
    let chain_config = Builder::new(network.into()).build();

    let input_owner_destination = input_owner_destination
        .map(|dest| parse_addressable(&chain_config, &dest))
        .transpose()?;

    let tx = Transaction::decode_all(&mut &transaction[..])
        .map_err(Error::InvalidTransactionEncoding)?;

    let input_utxos = decode_raw_array::<Option<TxOutput>>(input_utxos)
        .map_err(Error::InvalidInputUtxoEncoding)?;

    let ptx_additional_info = to_ptx_additional_info(&chain_config, &additional_info)?;

    let input_commitments = make_sighash_input_commitments_at_height(
        tx.inputs(),
        &input_utxos,
        &ptx_additional_info,
        &chain_config,
        BlockHeight::new(current_block_height),
    )?;

    let sighash = signature_hash(
        sighashtype.into(),
        &tx,
        &input_commitments,
        input_index as usize,
    )
    .map_err(Error::SighashCalculationError)?;

    let witness =
        InputWitness::decode_all(&mut &witness[..]).map_err(Error::InvalidWitnessEncoding)?;

    let input_utxo =
        input_utxos.get(input_index as usize).ok_or(Error::WrongInputIndexOrUtxoCount)?;
    let htlc = match input_utxo {
        Some(utxo) => match utxo {
            TxOutput::Htlc(_, htlc) => Some(htlc),

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
            | TxOutput::CreateOrder(_) => None,
        },
        None => None,
    };

    let sig_dest = if let Some(htlc) = htlc {
        ensure!(
            input_owner_destination.is_none(),
            Error::InputOwnerDestinationNotNeeded
        );

        let (htlc_spend, sighash_type) = extract_htlc_spend(&witness)?;

        let (raw_sig, dest) = match htlc_spend {
            AuthorizedHashedTimelockContractSpend::Spend(_, raw_sig) => {
                (raw_sig, htlc.spend_key.clone())
            }
            AuthorizedHashedTimelockContractSpend::Refund(raw_sig) => {
                (raw_sig, htlc.refund_key.clone())
            }
        };

        Some((StandardInputSignature::new(sighash_type, raw_sig), dest))
    } else {
        match witness {
            InputWitness::NoSignature(_) => {
                ensure!(
                    input_owner_destination.is_none(),
                    Error::InputOwnerDestinationNotNeeded
                );
                None
            }

            InputWitness::Standard(sig) => {
                let dest = input_owner_destination.ok_or(Error::InputOwnerDestinationNeeded)?;
                Some((sig, dest))
            }
        }
    };

    if let Some((sig, dest)) = sig_dest {
        sig.verify_signature(&chain_config, &dest, &sighash)
            .map_err(Error::SignatureVerificationError)?;
    }

    Ok(())
}
