// Copyright (c) 2025 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{
        signature::sighash::{
            self,
            input_commitments::{
                make_sighash_input_commitments_for_transaction_inputs_at_height, OrderInfoProvider,
                PoolInfoProvider, SighashInputCommitment,
            },
        },
        ChainConfig, OrderId, PoolId, TxInput, TxOutput,
    },
    primitives::BlockHeight,
};

use crate::{
    error::Error,
    utils::{
        internal_amount_from_simple_amount, output_value_from_simple_currency_amount,
        parse_addressable,
    },
};

pub fn make_sighash_input_commitments<'a>(
    tx_inputs: &[TxInput],
    input_utxos: &'a [Option<TxOutput>],
    inputs_info: &TxInputsAdditionalInfo,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Result<Vec<SighashInputCommitment<'a>>, Error> {
    Ok(
        make_sighash_input_commitments_for_transaction_inputs_at_height(
            tx_inputs,
            &sighash::input_commitments::TrivialUtxoProvider(input_utxos),
            inputs_info,
            inputs_info,
            chain_config,
            block_height,
        )?,
    )
}

pub type SighashInputCommitmentCreationError =
    sighash::input_commitments::SighashInputCommitmentCreationError<
        std::convert::Infallible,
        std::convert::Infallible,
        std::convert::Infallible,
    >;

pub struct TxInputsAdditionalInfo {
    pub pool_info: BTreeMap<PoolId, sighash::input_commitments::PoolInfo>,
    pub order_info: BTreeMap<OrderId, sighash::input_commitments::OrderInfo>,
}

impl TxInputsAdditionalInfo {
    pub fn from_tx_additional_info(
        chain_config: &ChainConfig,
        info: &crate::types::TxAdditionalInfo,
    ) -> Result<Self, Error> {
        let pool_info = info
            .pool_info
            .iter()
            .map(|(pool_id, pool_info)| {
                let pool_id = parse_addressable::<PoolId>(chain_config, pool_id)?;
                let pool_info = convert_pool_info(pool_info)?;
                Ok((pool_id, pool_info))
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;

        let order_info = info
            .order_info
            .iter()
            .map(|(order_id, order_info)| {
                let order_id = parse_addressable::<OrderId>(chain_config, order_id)?;
                let order_info = convert_order_info(chain_config, order_info)?;
                Ok((order_id, order_info))
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;

        Ok(Self {
            pool_info,
            order_info,
        })
    }
}

impl PoolInfoProvider for TxInputsAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_pool_info(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<sighash::input_commitments::PoolInfo>, Self::Error> {
        Ok(self.pool_info.get(pool_id).cloned())
    }
}

impl OrderInfoProvider for TxInputsAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_order_info(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<sighash::input_commitments::OrderInfo>, Self::Error> {
        Ok(self.order_info.get(order_id).cloned())
    }
}

fn convert_pool_info(
    info: &crate::types::PoolAdditionalInfo,
) -> Result<sighash::input_commitments::PoolInfo, Error> {
    let staker_balance = internal_amount_from_simple_amount(&info.staker_balance)?;

    Ok(sighash::input_commitments::PoolInfo { staker_balance })
}

fn convert_order_info(
    chain_config: &ChainConfig,
    info: &crate::types::OrderAdditionalInfo,
) -> Result<sighash::input_commitments::OrderInfo, Error> {
    let initially_asked =
        output_value_from_simple_currency_amount(chain_config, &info.initially_asked)?;
    let initially_given =
        output_value_from_simple_currency_amount(chain_config, &info.initially_given)?;

    let ask_balance = internal_amount_from_simple_amount(&info.ask_balance)?;
    let give_balance = internal_amount_from_simple_amount(&info.give_balance)?;

    Ok(sighash::input_commitments::OrderInfo {
        initially_asked,
        initially_given,
        ask_balance,
        give_balance,
    })
}
