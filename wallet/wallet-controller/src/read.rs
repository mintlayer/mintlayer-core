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

//! Read operations for the wallet

use std::collections::BTreeMap;

use common::{
    address::Address,
    chain::{
        ChainConfig, DelegationId, Destination, GenBlock, PoolId, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, DecimalAmount, Id},
};
use crypto::{
    key::hdkd::{child_number::ChildNumber, u31::U31},
    vrf::VRFPublicKey,
};
use futures::{stream::FuturesUnordered, TryStreamExt};
use node_comm::node_traits::NodeInterface;
use utils::tap_error_log::LogError;
use wallet::{
    account::{transaction_list::TransactionList, Currency, DelegationData, PoolData},
    DefaultWallet,
};
use wallet_types::{
    utxo_types::{UtxoStates, UtxoType, UtxoTypes},
    wallet_tx::TxData,
    with_locked::WithLocked,
    KeychainUsageState,
};

use crate::{types::Balances, ControllerError};

pub struct ReadOnlyController<'a, T> {
    wallet: &'a DefaultWallet,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    account_index: U31,
}

type MapAddressWithUsage<T> = BTreeMap<ChildNumber, (Address<T>, bool)>;

impl<'a, T: NodeInterface> ReadOnlyController<'a, T> {
    pub fn new(
        wallet: &'a DefaultWallet,
        rpc_client: T,
        chain_config: &'a ChainConfig,
        account_index: U31,
    ) -> Self {
        Self {
            wallet,
            rpc_client,
            chain_config,
            account_index,
        }
    }

    pub fn account_index(&self) -> U31 {
        self.account_index
    }

    pub fn get_balance(
        &self,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<T>> {
        self.wallet
            .get_balance(
                self.account_index,
                UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
                utxo_states,
                with_locked,
            )
            .map_err(ControllerError::WalletError)
    }

    pub async fn get_decimal_balance(
        &self,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Balances, ControllerError<T>> {
        let mut balances = self.get_balance(utxo_states, with_locked)?;

        let coins = balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);
        let coins = DecimalAmount::from_amount_minimal(coins, self.chain_config.coin_decimals());

        let tasks: FuturesUnordered<_> = balances
            .into_iter()
            .map(|(currency, amount)| async move {
                let token_id = match currency {
                    Currency::Coin => panic!("Removed just above"),
                    Currency::Token(token_id) => token_id,
                };

                super::fetch_token_info(&self.rpc_client, token_id).await.map(|info| {
                    let decimals = info.token_number_of_decimals();
                    let amount = DecimalAmount::from_amount_minimal(amount, decimals);
                    (token_id, amount)
                })
            })
            .collect();

        Ok(Balances::new(coins, tasks.try_collect().await?))
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ControllerError<T>> {
        self.wallet
            .get_utxos(self.account_index, utxo_types, utxo_states, with_locked)
            .map_err(ControllerError::WalletError)
    }

    pub fn pending_transactions(&self) -> Result<Vec<WithId<&'a Transaction>>, ControllerError<T>> {
        self.wallet
            .pending_transactions(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_transaction_list(
        &self,
        skip: usize,
        count: usize,
    ) -> Result<TransactionList, ControllerError<T>> {
        self.wallet
            .get_transaction_list(self.account_index, skip, count)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<&TxData, ControllerError<T>> {
        self.wallet
            .get_transaction(self.account_index, transaction_id)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_all_issued_addresses(
        &self,
    ) -> Result<BTreeMap<ChildNumber, Address<Destination>>, ControllerError<T>> {
        self.wallet
            .get_all_issued_addresses(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_all_issued_vrf_public_keys(
        &self,
    ) -> Result<MapAddressWithUsage<VRFPublicKey>, ControllerError<T>> {
        self.wallet
            .get_all_issued_vrf_public_keys(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_addresses_usage(&self) -> Result<&'a KeychainUsageState, ControllerError<T>> {
        self.wallet
            .get_addresses_usage(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    /// Get all addresses with usage information
    /// The boolean in the BTreeMap's value is true if the address is used, false is otherwise
    /// Note that the usage statistics follow strictly the rules of the wallet. For example,
    /// the initial wallet only stored information about the last used address, so the usage
    /// of all addresses after the first unused address will have the result `false`.
    pub fn get_addresses_with_usage(
        &self,
    ) -> Result<MapAddressWithUsage<Destination>, ControllerError<T>> {
        let addresses = self.get_all_issued_addresses()?;
        let usage = self.get_addresses_usage()?;

        Ok(addresses
            .into_iter()
            .map(|(child_number, address)| {
                let used = usage.last_used().is_some_and(|used| used >= child_number.get_index());
                (child_number, (address, used))
            })
            .collect())
    }

    /// Get all addresses with usage information
    /// The boolean in the BTreeMap's value is true if the address is used, false is otherwise
    /// Note that the usage statistics follow strictly the rules of the wallet. For example,
    /// the initial wallet only stored information about the last used address, so the usage
    /// of all addresses after the first unused address will have the result `false`.
    pub fn get_vrf_public_key_with_usage(
        &self,
    ) -> Result<MapAddressWithUsage<VRFPublicKey>, ControllerError<T>> {
        self.get_all_issued_vrf_public_keys()
    }

    pub async fn get_pool_ids(
        &self,
    ) -> Result<Vec<(PoolId, PoolData, Amount)>, ControllerError<T>> {
        let pools = self
            .wallet
            .get_pool_ids(self.account_index)
            .map_err(ControllerError::WalletError)?;

        let tasks: FuturesUnordered<_> = pools
            .into_iter()
            .map(|(pool_id, block_info)| self.get_pool_info(pool_id, block_info))
            .collect();

        tasks.try_collect().await
    }

    async fn get_pool_info(
        &self,
        pool_id: PoolId,
        pool_data: PoolData,
    ) -> Result<(PoolId, PoolData, Amount), ControllerError<T>> {
        self.rpc_client
            .get_stake_pool_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)
            .and_then(|balance| {
                balance.ok_or(ControllerError::SyncError(format!(
                    "Pool id {} from wallet not found in node",
                    Address::new(self.chain_config, &pool_id)?
                )))
            })
            .map(|balance| (pool_id, pool_data, balance))
            .log_err()
    }

    pub async fn get_delegations(&self) -> Result<Vec<(DelegationId, Amount)>, ControllerError<T>> {
        let delegations = self
            .wallet
            .get_delegations(self.account_index)
            .map_err(ControllerError::WalletError)?;

        let tasks: FuturesUnordered<_> = delegations
            .into_iter()
            .map(|(delegation_id, delegation_data)| {
                self.get_delegation_share(delegation_data, *delegation_id)
            })
            .collect();

        tasks.try_collect().await
    }

    pub fn get_created_blocks(&self) -> Result<Vec<Id<GenBlock>>, ControllerError<T>> {
        self.wallet
            .get_created_blocks(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    async fn get_delegation_share(
        &self,
        delegation_data: &DelegationData,
        delegation_id: DelegationId,
    ) -> Result<(DelegationId, Amount), ControllerError<T>> {
        if delegation_data.not_staked_yet {
            return Ok((delegation_id, Amount::ZERO));
        }

        self.rpc_client
            .get_delegation_share(delegation_data.pool_id, delegation_id)
            .await
            .map_err(ControllerError::NodeCallError)
            .and_then(|balance| {
                balance.ok_or(ControllerError::SyncError(format!(
                    "Delegation id {} from wallet not found in node",
                    Address::new(self.chain_config, &delegation_id)?
                )))
            })
            .map(|balance| (delegation_id, balance))
            .log_err()
    }
}
