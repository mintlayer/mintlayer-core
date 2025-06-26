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

use common::{
    chain::{
        block::BlockRewardTransactable,
        signature::{
            sighash::{
                self,
                input_commitments::{
                    make_sighash_input_commitments_for_kernel_inputs,
                    make_sighash_input_commitments_for_transaction_inputs_at_height,
                    SighashInputCommitment,
                },
            },
            Signable,
        },
        ChainConfig, OrderId, PoolId, SignedTransaction,
    },
    primitives::BlockHeight,
};

use super::{CoreContext, InputCheckError};

/// A wrapper that implements the "InfoProvider" traits from sighash::input_commitments;
/// this is needed to work around Rust's "orphan rule".
struct SighashInputCommitmentInfoProvidersImplementor<'a, T>(pub &'a T);

impl<AV> sighash::input_commitments::PoolInfoProvider
    for SighashInputCommitmentInfoProvidersImplementor<'_, AV>
where
    AV: pos_accounting::PoSAccountingView,
    pos_accounting::Error: From<<AV as pos_accounting::PoSAccountingView>::Error>,
{
    type Error = pos_accounting::Error;

    fn get_pool_info(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<sighash::input_commitments::PoolInfo>, Self::Error> {
        self.0
            .get_pool_data(*pool_id)?
            .map(|pool_data| {
                let staker_balance = pool_data.staker_balance()?;
                Ok(sighash::input_commitments::PoolInfo { staker_balance })
            })
            .transpose()
    }
}

impl<OV> sighash::input_commitments::OrderInfoProvider
    for SighashInputCommitmentInfoProvidersImplementor<'_, OV>
where
    OV: orders_accounting::OrdersAccountingView,
    orders_accounting::Error: From<<OV as orders_accounting::OrdersAccountingView>::Error>,
{
    type Error = orders_accounting::Error;

    fn get_order_info(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<sighash::input_commitments::OrderInfo>, Self::Error> {
        self.0
            .get_order_data(order_id)?
            .map(|order_data| {
                let ask_balance = self.0.get_ask_balance(order_id)?;
                let give_balance = self.0.get_give_balance(order_id)?;
                Ok(sighash::input_commitments::OrderInfo {
                    initially_asked: order_data.ask().clone(),
                    initially_given: order_data.give().clone(),
                    ask_balance,
                    give_balance,
                })
            })
            .transpose()
    }
}

pub trait SighashInputCommitmentsSource {
    fn get_input_commitments<'a, AV, OV>(
        &self,
        core_ctx: &'a CoreContext,
        pos_accounting: &'a AV,
        orders_accounting: &'a OV,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError>
    where
        AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
        OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>;
}

impl SighashInputCommitmentsSource for SignedTransaction {
    fn get_input_commitments<'a, AV, OV>(
        &self,
        core_ctx: &'a CoreContext,
        pos_accounting: &'a AV,
        orders_accounting: &'a OV,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError>
    where
        AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
        OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>,
    {
        Ok(
            make_sighash_input_commitments_for_transaction_inputs_at_height(
                self.inputs(),
                &core_ctx,
                &SighashInputCommitmentInfoProvidersImplementor(pos_accounting),
                &SighashInputCommitmentInfoProvidersImplementor(orders_accounting),
                chain_config,
                block_height,
            )?,
        )
    }
}

impl SighashInputCommitmentsSource for BlockRewardTransactable<'_> {
    fn get_input_commitments<'a, AV, OV>(
        &self,
        core_ctx: &'a CoreContext,
        _pos_accounting: &'a AV,
        _orders_accounting: &'a OV,
        _chain_config: &ChainConfig,
        _block_height: BlockHeight,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError>
    where
        AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
        OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>,
    {
        if let Some(kernel_inputs) = self.inputs() {
            let commitments =
                make_sighash_input_commitments_for_kernel_inputs(kernel_inputs, &core_ctx)?;

            Ok(commitments)
        } else {
            Ok(Vec::new())
        }
    }
}
