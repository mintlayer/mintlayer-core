// Copyright (c) 2024 RBB S.r.l
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

use std::convert::Infallible;

use common::chain::{
    signature::{
        inputsig::InputWitness, sighash::input_commitments::SighashInputCommitment,
        DestinationSigError, Transactable,
    },
    tokens::TokenId,
    ChainConfig, DelegationId, Destination, PoolId, SignedTransaction, TxInput, TxOutput,
};
use mintscript::{
    script::ScriptError, translate::InputInfoProvider, InputInfo, SignatureContext, TranslateInput,
};
use utils::ensure;

use super::{InputCheckError, InputCheckErrorPayload, PerInputData};

struct InputVerifyContextSignature<'a, T> {
    chain_config: &'a ChainConfig,
    tx: &'a T,
    outpoint_destination: &'a Destination,
    input_commitments: &'a [SighashInputCommitment<'a>],
    input_num: usize,
    input_data: PerInputData<'a>,
}

impl<T: Transactable> SignatureContext for InputVerifyContextSignature<'_, T> {
    type Tx = T;

    fn chain_config(&self) -> &ChainConfig {
        self.chain_config
    }

    fn transaction(&self) -> &Self::Tx {
        self.tx
    }

    fn input_commitments(&self) -> &[SighashInputCommitment] {
        self.input_commitments
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

impl<T: Transactable> mintscript::translate::SignatureInfoProvider
    for InputVerifyContextSignature<'_, T>
{
    fn get_pool_decommission_destination(
        &self,
        _pool_id: &PoolId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(Some(self.outpoint_destination.clone()))
    }

    fn get_delegation_spend_destination(
        &self,
        _delegation_id: &DelegationId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(Some(self.outpoint_destination.clone()))
    }

    fn get_tokens_authority(
        &self,
        _token_id: &TokenId,
    ) -> Result<Option<Destination>, tokens_accounting::Error> {
        Ok(Some(self.outpoint_destination.clone()))
    }

    fn get_orders_conclude_destination(
        &self,
        _order_id: &common::chain::OrderId,
    ) -> Result<Option<Destination>, orders_accounting::Error> {
        Ok(Some(self.outpoint_destination.clone()))
    }
}

impl<T: Transactable> InputInfoProvider for InputVerifyContextSignature<'_, T> {
    fn input_info(&self) -> &InputInfo {
        self.input_data.input_info()
    }

    fn witness(&self) -> &InputWitness {
        self.input_data.witness()
    }
}

// Prevent BlockRewardTransactable from being used here
pub trait SignatureOnlyVerifiable {}
impl SignatureOnlyVerifiable for SignedTransaction {}

// Note: the passed `outpoint_destination` value is only used in a limited number of scenarios
// (see `impl SignatureInfoProvider for InputVerifyContextSignature` above). In all other cases
// this parameter is ignored and the actual destination to verify the signature against is taken
// from other sources (e.g. from the utxo or, in the case of a v1 FillOrder input, it is always
// AnyoneCanSpend).
// TODO: the parameter should at least be made optional. Or maybe some kind of `SignatureInfoProvider`
// should be passed here instead of the plain `Destination`.
pub fn verify_tx_signature<T: Transactable + SignatureOnlyVerifiable>(
    chain_config: &ChainConfig,
    outpoint_destination: &Destination,
    tx: &T,
    input_commitments: &[SighashInputCommitment],
    input_num: usize,
    input_utxo: Option<TxOutput>,
) -> Result<(), InputCheckError> {
    let map_sig_err = |e: DestinationSigError| {
        InputCheckError::new(
            input_num,
            ScriptError::<DestinationSigError, Infallible, Infallible>::Signature(e),
        )
    };

    let inputs = tx
        .inputs()
        .ok_or(DestinationSigError::SignatureVerificationWithoutInputs)
        .map_err(map_sig_err)?;
    let input = inputs
        .get(input_num)
        .ok_or(DestinationSigError::InvalidInputIndex(
            input_num,
            inputs.len(),
        ))
        .map_err(map_sig_err)?;

    ensure!(
        inputs.len() == input_commitments.len(),
        map_sig_err(DestinationSigError::InvalidInputCommitmentsCountVsInputs(
            input_commitments.len(),
            inputs.len()
        ))
    );

    let input_info = match input {
        TxInput::Utxo(outpoint) => {
            let utxo = input_utxo.ok_or(InputCheckError::new(
                input_num,
                InputCheckErrorPayload::MissingUtxo(outpoint.clone()),
            ))?;
            InputInfo::Utxo {
                outpoint,
                utxo,
                utxo_source: None,
            }
        }
        TxInput::Account(outpoint) => InputInfo::Account { outpoint },
        TxInput::AccountCommand(_, command) => InputInfo::AccountCommand { command },
        TxInput::OrderAccountCommand(command) => InputInfo::OrderAccountCommand { command },
    };
    let input_witness = tx.signatures()[input_num]
        .clone()
        .ok_or(DestinationSigError::SignatureNotFound)
        .map_err(map_sig_err)?;

    let input_data = PerInputData::new(input_info, input_witness);
    let context = InputVerifyContextSignature {
        chain_config,
        tx,
        outpoint_destination,
        input_commitments,
        input_num,
        input_data,
    };
    let script = mintscript::translate::SignatureOnlyTx::translate_input(&context)
        .map_err(|e| InputCheckError::new(input_num, e))?;
    let mut checker = mintscript::ScriptChecker::signature_only(context);
    script.verify(&mut checker).map_err(|e| InputCheckError::new(input_num, e))?;

    Ok(())
}
