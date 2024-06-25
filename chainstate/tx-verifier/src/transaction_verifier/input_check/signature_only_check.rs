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

use chainstate_types::block_index_ancestor_getter;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        signature::{inputsig::InputWitness, DestinationSigError, Transactable},
        tokens::TokenId,
        ChainConfig, DelegationId, Destination, GenBlock, PoolId, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use mintscript::{
    translate::InputInfoProvider, InputInfo, SignatureContext, TimelockContext, TranslateInput,
    WitnessScript,
};

use crate::TransactionVerifierStorageRef;

use super::{InputCheckError, PerInputData, TransactionSourceForConnect};

struct InputVerifyContextSignature<'a, T> {
    transaction: &'a T,
}

impl<T: Transactable> SignatureContext for InputVerifyContextSignature<'_, T> {
    type Tx = T;

    fn chain_config(&self) -> &ChainConfig {
        todo!()
    }

    fn transaction(&self) -> &Self::Tx {
        todo!()
    }

    fn input_utxos(&self) -> &[Option<&TxOutput>] {
        todo!()
    }

    fn input_num(&self) -> usize {
        todo!()
    }
}

impl<T: Transactable> mintscript::translate::SignatureInfoProvider
    for InputVerifyContextSignature<'_, T>
{
    fn get_pool_decommission_destination(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        todo!()
    }

    fn get_delegation_spend_destination(
        &self,
        delegation_id: &DelegationId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        todo!()
    }

    fn get_tokens_authority(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<Destination>, tokens_accounting::Error> {
        todo!()
    }

    fn get_orders_conclude_destination(
        &self,
        order_id: &common::chain::OrderId,
    ) -> Result<Option<Destination>, orders_accounting::Error> {
        todo!()
    }
}

impl<T: Transactable> InputInfoProvider for InputVerifyContextSignature<'_, T> {
    fn input_info(&self) -> &InputInfo {
        todo!()
    }

    fn witness(&self) -> &InputWitness {
        todo!()
    }
}

pub fn verify_signature<T: Transactable>(
    chain_config: &ChainConfig,
    outpoint_destination: &Destination,
    tx: &T,
    inputs_utxos: &[Option<&TxOutput>],
    input_num: usize,
) -> Result<(), InputCheckError> {
    //let witness = tx.signatures()[input_num].clone().ok_or_else(|| {
    //    InputCheckError::new(
    //        n,
    //        ScriptError::Signature(DestinationSigError::SignatureNotFound),
    //    )
    //})?;
    //let input_data = PerInputData::new(, n, input, witness);

    let context = InputVerifyContextSignature { transaction: tx };
    let script = mintscript::translate::SignatureOnly::translate_input(&context)
        .map_err(|e| InputCheckError::new(input_num, e))?;
    let mut checker = mintscript::ScriptChecker::signature_only(context);
    script.verify(&mut checker).map_err(|e| InputCheckError::new(input_num, e))?;

    Ok(())
}
