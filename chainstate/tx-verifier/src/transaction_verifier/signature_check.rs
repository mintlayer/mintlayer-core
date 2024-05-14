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

use common::chain::{
    signature::{verify_signature, Transactable},
    ChainConfig, TxInput,
};
use utxo::UtxosView;

use super::{
    error::ConnectTransactionError, signature_destination_getter::SignatureDestinationGetter,
};

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
        println!("actual destination: {:?}", destination);
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
