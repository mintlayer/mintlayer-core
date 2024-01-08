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

use std::collections::BTreeMap;

use common::{address::Address, chain::SignedTransaction};
use utils::shallow_clone::ShallowClone;
use wallet_controller::{ControllerConfig, ControllerError, NodeInterface, UtxoStates, UtxoTypes};
use wallet_types::with_locked::WithLocked;

use crate::{
    rpc::{WalletRpc, WalletRpcServer},
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DecimalAmount,
        EmptyArgs, HexEncoded, NewAccountInfo, RpcError, TransactionOptions, TxOptionsOverrides,
        UtxoInfo,
    },
};

#[async_trait::async_trait]
impl WalletRpcServer for WalletRpc {
    async fn shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.wallet.shallow_clone().stop())
    }

    async fn best_block(&self, _: EmptyArgs) -> rpc::RpcResult<BlockInfo> {
        let res = rpc::handle_result(self.wallet.call(|w| w.best_block()).await)?;
        Ok(BlockInfo::from_tuple(res))
    }

    async fn create_account(&self, _: EmptyArgs) -> rpc::RpcResult<NewAccountInfo> {
        let (num, name) = rpc::handle_result(self.wallet.call(|w| w.create_account(None)).await)?;
        Ok(NewAccountInfo::new(num, name))
    }

    async fn issue_address(&self, account_index: AccountIndexArg) -> rpc::RpcResult<AddressInfo> {
        let account_index = account_index.index()?;
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let (child_number, destination) = rpc::handle_result(
            self.wallet
                .call_async(move |w| {
                    Box::pin(async move {
                        w.synced_controller(account_index, config).await?.new_address()
                    })
                })
                .await,
        )?;
        Ok(AddressInfo::new(child_number, destination))
    }

    async fn get_issued_addresses(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>> {
        let account_idx = account_index.index()?;
        let addresses: BTreeMap<_, _> = rpc::handle_result(
            self.wallet
                .call(move |controller| {
                    controller.readonly_controller(account_idx).get_addresses_with_usage()
                })
                .await,
        )?;
        let result = addresses
            .into_iter()
            .map(|(num, (addr, used))| AddressWithUsageInfo::new(num, addr, used))
            .collect();
        Ok(result)
    }

    async fn get_balance(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Balances> {
        let account_idx = account_index.index()?;
        let with_locked = WithLocked::Unlocked; // TODO make user-defined

        let balances: Balances = rpc::handle_result(
            self.wallet
                .call_async(move |w| {
                    Box::pin(async move {
                        let c = w.readonly_controller(account_idx);
                        c.get_decimal_balance(UtxoStates::ALL, with_locked).await
                    })
                })
                .await,
        )?;
        Ok(balances)
    }

    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<UtxoInfo>> {
        let account_idx = account_index.index()?;
        let utxos: Vec<_> = rpc::handle_result(
            self.wallet
                .call(move |w| {
                    w.readonly_controller(account_idx).get_utxos(
                        UtxoTypes::ALL,
                        UtxoStates::ALL,
                        WithLocked::Any,
                    )
                })
                .await,
        )?;
        Ok(utxos.into_iter().map(UtxoInfo::from_tuple).collect())
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(self.node.submit_transaction(tx.take(), options).await)
    }

    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount_str: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount_str.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        let acct = account_index.index()?;
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller
                            .synced_controller(acct, config)
                            .await?
                            .send_to_address(address, amount, vec![])
                            .await?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
                .await,
        )
    }
}
