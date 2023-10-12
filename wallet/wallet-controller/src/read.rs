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
    chain::{ChainConfig, DelegationId, Destination, PoolId, Transaction, TxOutput, UtxoOutPoint},
    primitives::{id::WithId, Amount},
};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};
use futures::{stream::FuturesUnordered, TryStreamExt};
use node_comm::node_traits::NodeInterface;
use utils::tap_error_log::LogError;
use wallet::{
    account::{transaction_list::TransactionList, Currency, DelegationData},
    DefaultWallet,
};
use wallet_types::{
    utxo_types::{UtxoStates, UtxoType, UtxoTypes},
    with_locked::WithLocked,
    BlockInfo, KeychainUsageState,
};

use crate::ControllerError;

pub struct ReadOnlyController<'a, T> {
    wallet: &'a DefaultWallet,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    account_index: U31,
}

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
                UtxoType::Transfer
                    | UtxoType::LockThenTransfer
                    | UtxoType::MintTokens
                    | UtxoType::IssueNft,
                utxo_states,
                with_locked,
            )
            .map_err(ControllerError::WalletError)
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<BTreeMap<UtxoOutPoint, TxOutput>, ControllerError<T>> {
        self.wallet
            .get_utxos(self.account_index, utxo_types, utxo_states, with_locked)
            .map_err(ControllerError::WalletError)
    }

    pub fn pending_transactions(&self) -> Result<Vec<&'a WithId<Transaction>>, ControllerError<T>> {
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

    pub fn get_all_issued_addresses(
        &self,
    ) -> Result<BTreeMap<ChildNumber, Address<Destination>>, ControllerError<T>> {
        self.wallet
            .get_all_issued_addresses(self.account_index)
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
    #[allow(clippy::type_complexity)]
    pub fn get_addresses_with_usage(
        &self,
    ) -> Result<BTreeMap<ChildNumber, (Address<Destination>, bool)>, ControllerError<T>> {
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

    pub async fn get_pool_ids(
        &self,
    ) -> Result<Vec<(PoolId, BlockInfo, Amount)>, ControllerError<T>> {
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
        block_info: BlockInfo,
    ) -> Result<(PoolId, BlockInfo, Amount), ControllerError<T>> {
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
            .map(|balance| (pool_id, block_info, balance))
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
