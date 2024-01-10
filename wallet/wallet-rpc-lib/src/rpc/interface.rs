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

use common::{
    chain::{GenBlock, SignedTransaction},
    primitives::Id,
};
use crypto::key::PublicKey;
use wallet_types::with_locked::WithLocked;

use crate::types::{
    AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DecimalAmount,
    DelegationInfo, EmptyArgs, HexEncoded, JsonValue, NewAccountInfo, NewDelegation, PoolInfo,
    PublicKeyInfo, TransactionOptions, TxOptionsOverrides,
};

#[rpc::rpc(server)]
trait WalletRpc {
    #[method(name = "shutdown")]
    async fn shutdown(&self) -> rpc::RpcResult<()>;

    #[method(name = "sync")]
    async fn sync(&self) -> rpc::RpcResult<()>;

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

    #[method(name = "issue_public_key")]
    async fn issue_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<PublicKeyInfo>;

    #[method(name = "get_balance")]
    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances>;

    #[method(name = "get_utxos")]
    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<JsonValue>>;

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
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "create_stake_pool")]
    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_key: Option<HexEncoded<PublicKey>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "decommission_stake_pool")]
    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "create_delegation")]
    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation>;

    #[method(name = "delegate_staking")]
    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "send_from_delegation_to_address")]
    async fn send_from_delegation_to_address(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "start_staking")]
    async fn start_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()>;

    #[method(name = "stop_staking")]
    async fn stop_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()>;

    #[method(name = "list_pool_ids")]
    async fn list_pool_ids(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<PoolInfo>>;

    #[method(name = "list_delegation_ids")]
    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>>;

    #[method(name = "list_created_blocks_ids")]
    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<GenBlock>>>;
}
