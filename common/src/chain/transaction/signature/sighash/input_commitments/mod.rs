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

mod info_providers;

use std::borrow::Cow;

use strum::{EnumDiscriminants, EnumIter};

use serialization::{Decode, Encode};
use utils::cow_utils::CowUtils as _;

use crate::chain::{TxInput, TxOutput, UtxoOutPoint};

pub use info_providers::{TrivialUtxoProvider, UtxoProvider};

/// Extra data related to an input to which we commit when signing a transaction.
///
/// This is encode-compatible with Option<&TxOutput>
#[derive(Clone, Debug, Encode, Decode, Eq, PartialEq, EnumDiscriminants)]
#[strum_discriminants(name(SighashInputCommitmentTag), derive(EnumIter))]
pub enum SighashInputCommitment<'a> {
    #[codec(index = 0)]
    None,

    #[codec(index = 1)]
    Utxo(Cow<'a, TxOutput>),
}

impl SighashInputCommitment<'_> {
    pub fn deep_clone(&self) -> SighashInputCommitment<'static> {
        match self {
            SighashInputCommitment::None => SighashInputCommitment::None,
            SighashInputCommitment::Utxo(cow) => SighashInputCommitment::Utxo(cow.to_owned_cow()),
        }
    }
}

pub fn make_sighash_input_commitments_for_kernel_input_utxos(
    kernel_input_utxos: &'_ [TxOutput],
) -> Vec<SighashInputCommitment<'_>> {
    kernel_input_utxos
        .iter()
        .map(|utxo| SighashInputCommitment::Utxo(Cow::Borrowed(utxo)))
        .collect()
}

pub fn make_sighash_input_commitments_for_kernel_inputs<'a, UP>(
    kernel_inputs: &[TxInput],
    utxo_provider: &UP,
) -> Result<
    Vec<SighashInputCommitment<'a>>,
    SighashInputCommitmentCreationError<<UP as UtxoProvider<'a>>::Error>,
>
where
    UP: UtxoProvider<'a>,
{
    kernel_inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_provider
                    .get_utxo(idx, outpoint)
                    .map_err(|err| {
                        SighashInputCommitmentCreationError::UtxoProviderError(err, idx)
                    })?
                    .ok_or_else(|| {
                        SighashInputCommitmentCreationError::UtxoNotFound(outpoint.clone(), idx)
                    })?;
                Ok(SighashInputCommitment::Utxo(utxo))
            }
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => Err(
                SighashInputCommitmentCreationError::NonUtxoKernelInput(input.clone(), idx),
            ),
        })
        .collect::<Result<_, _>>()
}

#[allow(clippy::type_complexity)]
pub fn make_sighash_input_commitments_for_transaction_inputs<'a, UP>(
    tx_inputs: &[TxInput],
    utxo_provider: &UP,
) -> Result<
    Vec<SighashInputCommitment<'a>>,
    SighashInputCommitmentCreationError<<UP as UtxoProvider<'a>>::Error>,
>
where
    UP: UtxoProvider<'a>,
{
    let commitments = tx_inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_provider
                    .get_utxo(idx, outpoint)
                    .map_err(|err| {
                        SighashInputCommitmentCreationError::UtxoProviderError(err, idx)
                    })?
                    .ok_or_else(|| {
                        SighashInputCommitmentCreationError::UtxoNotFound(outpoint.clone(), idx)
                    })?;

                Ok(SighashInputCommitment::Utxo(utxo))
            }
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => Ok(SighashInputCommitment::None),
        })
        .collect::<Result<_, _>>()?;

    Ok(commitments)
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum SighashInputCommitmentCreationError<UPE>
where
    UPE: std::error::Error,
{
    #[error("Utxo provider error: {0} (input index: {1})")]
    UtxoProviderError(UPE, /*input index*/ usize),

    #[error("Non-utxo kernel input: {0:?} (input index: {1})")]
    NonUtxoKernelInput(TxInput, /*input index*/ usize),

    #[error("Utxo not found: {0:?} (input index: {1})")]
    UtxoNotFound(UtxoOutPoint, /*input index*/ usize),
}
