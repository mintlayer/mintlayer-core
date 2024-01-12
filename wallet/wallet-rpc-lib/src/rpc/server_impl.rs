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

use common::{
    address::dehexify::to_dehexified_json,
    chain::{GenBlock, SignedTransaction},
    primitives::Id,
};
use crypto::key::PublicKey;
use wallet_controller::{ControllerConfig, UtxoStates, UtxoTypes};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

use crate::{
    rpc::{WalletRpc, WalletRpcServer},
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DecimalAmount,
        DelegationInfo, EmptyArgs, HexEncoded, JsonValue, NewAccountInfo, NewDelegation, PoolInfo,
        PublicKeyInfo, TransactionOptions, TxOptionsOverrides, UtxoInfo,
    },
};

#[async_trait::async_trait]
impl WalletRpcServer for WalletRpc {
    async fn shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.shutdown())
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> rpc::RpcResult<()> {
        let whether_to_store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };
        rpc::handle_result(
            self.create_wallet(path.into(), whether_to_store_seed_phrase, mnemonic)
                .await
                .map(|_| ()),
        )
    }

    async fn open_wallet(&self, path: String, password: Option<String>) -> rpc::RpcResult<()> {
        rpc::handle_result(self.open_wallet(path.into(), password).await)
    }

    async fn close_wallet(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.close_wallet().await)
    }

    async fn sync(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.sync().await)
    }

    async fn best_block(&self, empty_args: EmptyArgs) -> rpc::RpcResult<BlockInfo> {
        rpc::handle_result(self.best_block(empty_args).await)
    }

    async fn create_account(&self, _empty_args: EmptyArgs) -> rpc::RpcResult<NewAccountInfo> {
        rpc::handle_result(self.create_account(None).await)
    }

    async fn issue_address(&self, account_index: AccountIndexArg) -> rpc::RpcResult<AddressInfo> {
        rpc::handle_result(self.issue_address(account_index.index()?).await)
    }

    async fn issue_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<PublicKeyInfo> {
        rpc::handle_result(self.issue_public_key(account_index.index()?).await)
    }

    async fn get_issued_addresses(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>> {
        rpc::handle_result(self.get_issued_addresses(account_index.index()?).await)
    }

    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances> {
        rpc::handle_result(
            self.get_balance(
                account_index.index()?,
                UtxoStates::ALL,
                with_locked.unwrap_or(WithLocked::Unlocked),
            )
            .await,
        )
    }

    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<JsonValue>> {
        let utxos = self
            .get_utxos(
                account_index.index()?,
                UtxoTypes::ALL,
                UtxoStates::ALL,
                WithLocked::Unlocked,
            )
            .await?;

        let result = utxos
            .into_iter()
            .map(|utxo| to_dehexified_json(&self.chain_config, UtxoInfo::from_tuple(utxo)))
            .collect::<Result<Vec<_>, _>>();

        rpc::handle_result(result)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(self.submit_raw_transaction(tx, options).await)
    }

    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount_str: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.send_coins(account_index.index()?, address, amount_str, vec![], config)
                .await,
        )
    }

    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_key: Option<HexEncoded<PublicKey>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.create_stake_pool(
                account_index.index()?,
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_key,
                config,
            )
            .await,
        )
    }

    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.decommission_stake_pool(account_index.index()?, pool_id, config).await,
        )
    }

    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.create_delegation(account_index.index()?, address, pool_id, config).await,
        )
    }

    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.delegate_staking(account_index.index()?, amount, delegation_id, config)
                .await,
        )
    }

    async fn send_from_delegation_to_address(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.send_from_delegation_to_address(
                account_index.index()?,
                address,
                amount,
                delegation_id,
                config,
            )
            .await,
        )
    }

    async fn start_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.start_staking(account_index.index()?).await)
    }

    async fn stop_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.stop_staking(account_index.index()?).await)
    }

    async fn list_pool_ids(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<PoolInfo>> {
        rpc::handle_result(self.list_pool_ids(account_index.index()?).await)
    }

    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>> {
        rpc::handle_result(self.list_delegation_ids(account_index.index()?).await)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<GenBlock>>> {
        rpc::handle_result(self.list_created_blocks_ids(account_index.index()?).await)
    }
}
