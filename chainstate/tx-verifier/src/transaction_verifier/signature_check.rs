// Copyright (c) 2023 RBB S.r.l
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

use chainstate_types::{block_index_ancestor_getter, GenBlockIndex};
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        signature::{verify_signature, Transactable},
        ChainConfig, GenBlock, TxInput,
    },
    primitives::Id,
};
use mintscript::{
    helpers::{InputUtxoBlockInfo, SourceTransactionInfo},
    script::MintScript,
};
use pos_accounting::PoSAccountingView;
use utxo::UtxosView;

use crate::TransactionVerifierStorageRef;

use super::{
    error::ConnectTransactionError, signature_destination_getter::SignatureDestinationGetter,
    TransactionSourceForConnect,
};

#[allow(dead_code)]
pub fn check_scripts_for_tx<S, U, T, P>(
    chain_config: &ChainConfig,
    storage: &S,
    utxo_view: &U,
    accounting_view: &P,
    tx_source: &TransactionSourceForConnect,
    median_time_past: &BlockTimestamp,
    transactable: &T,
) -> Result<(), ConnectTransactionError>
where
    S: TransactionVerifierStorageRef,
    U: UtxosView,
    T: Transactable,
    P: PoSAccountingView<Error = pos_accounting::Error>,
{
    let tx_source_info = SourceTransactionInfo {
        block_height: tx_source.expected_block_height(),
        block_timestamp: *median_time_past,
    };

    let starting_point: GenBlockIndex = match tx_source {
        TransactionSourceForConnect::Chain { new_block_index } => {
            (*new_block_index).clone().into_gen_block_index()
        }
        TransactionSourceForConnect::Mempool {
            current_best,
            effective_height: _,
        } => (*current_best).clone(),
    };

    let inputs = match transactable.inputs() {
        Some(ins) => ins,
        None => return Ok(()),
    };

    let inputs_utxos = inputs
        .iter()
        .map(|input| match input {
            TxInput::Utxo(outpoint) => utxo_view
                .utxo(outpoint)
                .map_err(|_| utxo::Error::ViewRead)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent(
                    outpoint.clone(),
                ))
                .map(Some),
            TxInput::Account(..) | TxInput::AccountCommand(..) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;

    inputs_utxos.iter().enumerate().try_for_each(|(input_idx, utxo)| match utxo {
        Some(utxo) => {
            let input_utxos = inputs_utxos
                .iter()
                .map(|utxo_op| utxo_op.clone().map(|utxo| utxo.take_output()))
                .collect::<Vec<_>>();
            let script = MintScript::from_output_for_tx(
                chain_config,
                utxo.output().clone(),
                transactable,
                &input_utxos.iter().map(|v| v.as_ref()).collect::<Vec<_>>(),
                input_idx,
                utxo_view,
                accounting_view,
            )
            .unwrap_or(MintScript::Bool(false));

            let utxo_block_height = utxo.source().blockchain_height()?;

            let block_index_getter =
                |db_tx: &S, _cc: &ChainConfig, id: &Id<GenBlock>| db_tx.get_gen_block_index(id);

            let source_block_index = block_index_ancestor_getter(
                block_index_getter,
                storage,
                chain_config,
                (&starting_point).into(),
                utxo_block_height,
            )
            .map_err(|e| {
                ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                    e,
                    utxo_block_height,
                )
            })?;

            let input_utxo_block_info = InputUtxoBlockInfo {
                block_height: utxo.source().blockchain_height()?,
                block_timestamp: source_block_index.block_timestamp(),
            };

            if !script
                .try_into_bool(chain_config, &tx_source_info, &input_utxo_block_info)
                .unwrap_or(false)
            {
                return Err(ConnectTransactionError::ScriptEvaluationFailed(
                    mintscript::script::error::Error::ScriptEvalFailed,
                ));
            }
            Ok(())
        }
        None => Ok(()),
    })?;

    Ok(())
}

pub fn verify_signatures<U, T>(
    chain_config: &ChainConfig,
    utxo_view: &U,
    transactable: &T,
    destination_getter: SignatureDestinationGetter,
) -> Result<(), ConnectTransactionError>
where
    U: UtxosView,
    T: Transactable,
{
    let inputs = match transactable.inputs() {
        Some(ins) => ins,
        None => return Ok(()),
    };

    let inputs_utxos = inputs
        .iter()
        .map(|input| match input {
            TxInput::Utxo(outpoint) => utxo_view
                .utxo(outpoint)
                .map_err(|_| utxo::Error::ViewRead)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent(
                    outpoint.clone(),
                ))
                .map(|utxo| Some(utxo.take_output())),
            TxInput::Account(..) | TxInput::AccountCommand(..) => Ok(None),
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;
    let inputs_utxos = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

    inputs.iter().enumerate().try_for_each(|(input_idx, input)| {
        // TODO: ensure that signature verification is tested in the test-suite, they seem to be tested only internally
        let destination = destination_getter.call(input)?;
        verify_signature(
            chain_config,
            &destination,
            transactable,
            &inputs_utxos,
            input_idx,
        )
        .map_err(ConnectTransactionError::SignatureVerificationFailed)
    })
}

// TODO: unit tests
