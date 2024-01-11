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

use common::{
    address::{dehexify::to_dehexified_json, Address},
    chain::{DelegationId, GenBlock, PoolId, SignedTransaction},
    primitives::{per_thousand::PerThousand, Amount, Id},
};
use crypto::key::PublicKey;
use utils::shallow_clone::ShallowClone;
use wallet_controller::{ControllerConfig, ControllerError, NodeInterface, UtxoStates, UtxoTypes};
use wallet_types::{wallet_tx, with_locked::WithLocked};

use crate::{
    rpc::{WalletRpc, WalletRpcServer},
    service::WalletManagement,
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DecimalAmount,
        DelegationInfo, EmptyArgs, HexEncoded, JsonValue, NewAccountInfo, NewDelegation, PoolInfo,
        PublicKeyInfo, RpcError, TransactionOptions, TxOptionsOverrides, UtxoInfo,
    },
};

#[async_trait::async_trait]
impl WalletRpcServer for WalletRpc {
    async fn shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.wallet.shallow_clone().stop())
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.wallet
                .manage_async(WalletManagement::Create {
                    wallet_path: path.into(),
                    whether_to_store_seed_phrase: store_seed_phrase,
                    mnemonic,
                })
                .await,
        )
    }

    async fn open_wallet(&self, path: String, password: Option<String>) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.wallet
                .manage_async(WalletManagement::Open {
                    wallet_path: path.into(),
                    password,
                })
                .await,
        )
    }

    async fn close_wallet(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.wallet.manage_async(WalletManagement::Close).await)
    }

    async fn sync(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.wallet
                .call_async(move |w| Box::pin(async move { w.sync_once().await }))
                .await,
        )
    }

    async fn best_block(&self, _: EmptyArgs) -> rpc::RpcResult<BlockInfo> {
        let res = rpc::handle_result(self.wallet.call(|w| Ok(w.best_block())).await)?;
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

    async fn issue_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<PublicKeyInfo> {
        let account_index = account_index.index()?;
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let publick_key = rpc::handle_result(
            self.wallet
                .call_async(move |w| {
                    Box::pin(async move {
                        w.synced_controller(account_index, config).await?.new_public_key()
                    })
                })
                .await,
        )?;
        Ok(PublicKeyInfo::new(publick_key))
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

    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances> {
        let account_idx = account_index.index()?;

        let balances: Balances = rpc::handle_result(
            self.wallet
                .call_async(move |w| {
                    Box::pin(async move {
                        let c = w.readonly_controller(account_idx);
                        c.get_decimal_balance(
                            UtxoStates::ALL,
                            with_locked.unwrap_or(WithLocked::Unlocked),
                        )
                        .await
                    })
                })
                .await,
        )?;
        Ok(balances)
    }

    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<JsonValue>> {
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

    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_key: Option<HexEncoded<PublicKey>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let cost_per_block =
            cost_per_block.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let decommission_key = decommission_key.map(HexEncoded::take);

        let margin_ratio_per_thousand = PerThousand::from_decimal_str(&margin_ratio_per_thousand)
            .ok_or(RpcError::InvalidMarginRatio)?;

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
                            .create_stake_pool_tx(
                                amount,
                                decommission_key,
                                margin_ratio_per_thousand,
                                cost_per_block,
                            )
                            .await?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
                .await,
        )
    }

    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let acct = account_index.index()?;
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller
                            .synced_controller(acct, config)
                            .await?
                            .decommission_stake_pool(pool_id)
                            .await?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
                .await,
        )
    }

    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation> {
        let acct = account_index.index()?;
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        let address =
            Address::from_str(&self.chain_config, &address).map_err(|_| RpcError::InvalidPoolId)?;

        let pool_id = Address::from_str(&self.chain_config, &pool_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        let delegation_id = controller
                            .synced_controller(acct, config)
                            .await?
                            .create_delegation(address, pool_id)
                            .await?;
                        Ok::<DelegationId, ControllerError<_>>(delegation_id)
                    })
                })
                .await,
        )
        .map(|delegation_id: DelegationId| NewDelegation {
            delegation_id: Address::new(&self.chain_config, &delegation_id)
                .expect("addressable delegation id")
                .get()
                .to_owned(),
        })
    }

    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()> {
        let acct = account_index.index()?;
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        let delegation_id = Address::from_str(&self.chain_config, &delegation_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller
                            .synced_controller(acct, config)
                            .await?
                            .delegate_staking(amount, delegation_id)
                            .await?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
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
        let decimals = self.chain_config.coin_decimals();
        let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
        let address = Address::from_str(&self.chain_config, &address)
            .map_err(|_| RpcError::InvalidAddress)?;
        let acct = account_index.index()?;
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        let delegation_id = Address::from_str(&self.chain_config, &delegation_id)
            .and_then(|addr| addr.decode_object(&self.chain_config))
            .map_err(|_| RpcError::InvalidPoolId)?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller
                            .synced_controller(acct, config)
                            .await?
                            .send_to_address_from_delegation(address, amount, delegation_id)
                            .await?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
                .await,
        )
    }

    async fn start_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        let config = ControllerConfig { in_top_x_mb: 5 }; // irrelevant for issuing addresses
        let acct = account_index.index()?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(async move {
                        controller.synced_controller(acct, config).await?.start_staking()?;
                        Ok::<(), ControllerError<_>>(())
                    })
                })
                .await,
        )
    }

    async fn stop_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        let acct = account_index.index()?;

        rpc::handle_result(
            self.wallet
                .call(move |controller| {
                    controller.stop_staking(acct)?;
                    Ok::<(), ControllerError<_>>(())
                })
                .await,
        )
    }

    async fn list_pool_ids(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<PoolInfo>> {
        let acct = account_index.index()?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(
                        async move { controller.readonly_controller(acct).get_pool_ids().await },
                    )
                })
                .await,
        )
        .map(|pools: Vec<(PoolId, wallet_tx::BlockInfo, Amount)>| {
            pools
                .into_iter()
                .map(|(pool_id, block_data, balance)| {
                    PoolInfo::new(pool_id, block_data, balance, &self.chain_config)
                })
                .collect()
        })
    }

    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>> {
        let acct = account_index.index()?;

        rpc::handle_result(
            self.wallet
                .call_async(move |controller| {
                    Box::pin(
                        async move { controller.readonly_controller(acct).get_delegations().await },
                    )
                })
                .await,
        )
        .map(|delegations: Vec<(DelegationId, Amount)>| {
            delegations
                .into_iter()
                .map(|(delegation_id, balance)| {
                    DelegationInfo::new(delegation_id, balance, &self.chain_config)
                })
                .collect()
        })
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<GenBlock>>> {
        let acct = account_index.index()?;

        rpc::handle_result(
            self.wallet
                .call(move |controller| controller.readonly_controller(acct).get_created_blocks())
                .await,
        )
    }
}
