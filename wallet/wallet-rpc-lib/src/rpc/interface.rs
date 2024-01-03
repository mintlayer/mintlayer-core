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

use common::chain::SignedTransaction;

use crate::types::{AmountString, NewAccountInfo, UtxoInfo};

use super::types::{
    AccountIndexArg, AddressInfo, AddressWithUsageInfo, BalanceInfo, BlockInfo, EmptyArgs,
    HexEncoded, TxOptionsOverrides,
};

#[rpc::rpc(server)]
trait WalletRpc {
    #[method(name = "shutdown")]
    async fn shutdown(&self) -> rpc::RpcResult<()>;

    #[method(name = "best_block")]
    async fn best_block(&self, options: EmptyArgs) -> rpc::RpcResult<BlockInfo>;

    #[method(name = "create_account")]
    async fn create_account(&self, options: EmptyArgs) -> rpc::RpcResult<NewAccountInfo>;

    #[method(name = "get_issued_addresses")]
    async fn get_issued_addresses(
        &self,
        options: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>>;

    #[method(name = "issue_address")]
    async fn issue_address(&self, account_index: AccountIndexArg) -> rpc::RpcResult<AddressInfo>;

    #[method(name = "get_balance")]
    async fn get_balance(&self, account_index: AccountIndexArg) -> rpc::RpcResult<BalanceInfo>;

    #[method(name = "get_utxos")]
    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<UtxoInfo>>;

    #[method(name = "submit_raw_transaction")]
    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<()>;

    #[method(name = "send_coins")]
    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: AmountString,
        options: EmptyArgs,
    ) -> rpc::RpcResult<()>;
}
