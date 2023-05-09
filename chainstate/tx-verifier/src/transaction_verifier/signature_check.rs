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
    ChainConfig,
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
        .map(|input| {
            let outpoint = input.outpoint();
            utxo_view
                .utxo(outpoint)
                .map_err(|_| utxo::Error::ViewRead)?
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
                .map(|utxo| utxo.take_output())
        })
        .collect::<Result<Vec<_>, ConnectTransactionError>>()?;

    inputs_utxos.iter().enumerate().try_for_each(|(input_idx, utxo)| {
        // TODO: ensure that signature verification is tested in the test-suite, they seem to be tested only internally
        let destination = destination_getter.call(utxo)?;
        verify_signature(
            chain_config,
            &destination,
            transactable,
            &inputs_utxos.iter().collect::<Vec<_>>(),
            input_idx,
        )
        .map_err(ConnectTransactionError::SignatureVerificationFailed)
    })
}

// TODO: unit tests
