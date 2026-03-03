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

use super::*;

use crate::schema::{self as db};
use common::chain::UtxoOutPoint;
use storage::MakeMapRef;
use utils::log_error;
use utxo::Utxo;

impl<B: storage::SharedBackend> StoreTxRo<'_, B> {
    /// Dump raw database contents
    #[log_error]
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.0.dump_raw().map_err(crate::Error::from)
    }

    /// Collect and return all utxos from the storage
    #[log_error]
    pub fn read_utxo_set(&self) -> crate::Result<BTreeMap<UtxoOutPoint, Utxo>> {
        self.0
            .get::<db::DBUtxo, _>()
            .prefix_iter_decoded(&())
            .map(Iterator::collect)
            .map_err(crate::Error::from)
    }

    /// Collect and return all tip accounting data from storage
    #[log_error]
    pub fn read_pos_accounting_data_tip(&self) -> crate::Result<pos_accounting::PoSAccountingData> {
        let pool_data = self
            .0
            .get::<db::DBAccountingPoolDataTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let pool_balances = self
            .0
            .get::<db::DBAccountingPoolBalancesTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let delegation_data = self
            .0
            .get::<db::DBAccountingDelegationDataTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let delegation_balances = self
            .0
            .get::<db::DBAccountingDelegationBalancesTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }

    /// Collect and return all sealed accounting data from storage
    #[log_error]
    pub fn read_pos_accounting_data_sealed(
        &self,
    ) -> crate::Result<pos_accounting::PoSAccountingData> {
        let pool_data = self
            .0
            .get::<db::DBAccountingPoolDataSealed, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let pool_balances = self
            .0
            .get::<db::DBAccountingPoolBalancesSealed, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let delegation_data = self
            .0
            .get::<db::DBAccountingDelegationDataSealed, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let delegation_balances = self
            .0
            .get::<db::DBAccountingDelegationBalancesSealed, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesSealed, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }

    #[log_error]
    pub fn read_tokens_accounting_data(
        &self,
    ) -> crate::Result<tokens_accounting::TokensAccountingData> {
        let token_data = self
            .0
            .get::<db::DBTokensData, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let circulating_supply = self
            .0
            .get::<db::DBTokensCirculatingSupply, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        Ok(tokens_accounting::TokensAccountingData {
            token_data,
            circulating_supply,
        })
    }

    #[log_error]
    pub fn read_orders_accounting_data(
        &self,
    ) -> crate::Result<orders_accounting::OrdersAccountingData> {
        let order_data = self
            .0
            .get::<db::DBOrdersData, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let ask_balances = self
            .0
            .get::<db::DBOrdersAskBalances, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        let give_balances = self
            .0
            .get::<db::DBOrdersGiveBalances, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<_, _>>();

        Ok(orders_accounting::OrdersAccountingData {
            order_data,
            ask_balances,
            give_balances,
        })
    }
}
