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

use common::chain::{htlc::HtlcSecret, Destination, PoolId, TxOutput};

use crate::account::PoolData;

#[derive(Clone, Copy, Debug)]
pub enum HtlcSpendingCondition {
    WithSecret,
    WithMultisig,
    Skip,
}

impl HtlcSpendingCondition {
    pub fn from_opt_secrets_array_item(
        secrets: Option<&[Option<HtlcSecret>]>,
        index: usize,
    ) -> Self {
        secrets.map_or(Self::Skip, |secrets| {
            secrets
                .get(index)
                .and_then(Option::as_ref)
                .map_or(Self::WithMultisig, |_: &HtlcSecret| Self::WithSecret)
        })
    }
}

pub fn get_tx_output_destination<'a, PoolDataGetter>(
    txo: &TxOutput,
    pool_data_getter: &PoolDataGetter,
    htlc_spending: HtlcSpendingCondition,
) -> Option<Destination>
where
    PoolDataGetter: Fn(&PoolId) -> Option<&'a PoolData>,
{
    match txo {
        TxOutput::Transfer(_, d)
        | TxOutput::LockThenTransfer(_, d, _)
        | TxOutput::IssueNft(_, _, d) => Some(d.clone()),
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            pool_data_getter(pool_id).map(|pool_data| pool_data.decommission_key.clone())
        }
        TxOutput::CreateStakePool(_, data) => Some(data.decommission_key().clone()),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
        TxOutput::Htlc(_, htlc) => match htlc_spending {
            HtlcSpendingCondition::WithSecret => Some(htlc.spend_key.clone()),
            HtlcSpendingCondition::WithMultisig => Some(htlc.refund_key.clone()),
            HtlcSpendingCondition::Skip => None,
        },
    }
}

pub fn get_all_tx_output_destinations<'a, PoolDataGetter>(
    txo: &TxOutput,
    pool_data_getter: &PoolDataGetter,
) -> Option<Vec<Destination>>
where
    PoolDataGetter: Fn(&PoolId) -> Option<&'a PoolData>,
{
    match txo {
        TxOutput::Transfer(_, d)
        | TxOutput::LockThenTransfer(_, d, _)
        | TxOutput::IssueNft(_, _, d) => Some(vec![d.clone()]),
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            pool_data_getter(pool_id).map(|pool_data| vec![pool_data.decommission_key.clone()])
        }
        TxOutput::CreateStakePool(_, data) => Some(vec![data.decommission_key().clone()]),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
        TxOutput::Htlc(_, htlc) => Some(vec![htlc.spend_key.clone(), htlc.refund_key.clone()]),
    }
}
