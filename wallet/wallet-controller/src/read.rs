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
    primitives::{id::WithId, Amount, Id},
};
use crypto::{
    key::{
        extended::ExtendedPublicKey,
        hdkd::{child_number::ChildNumber, u31::U31},
    },
    vrf::VRFPublicKey,
};
use futures::{stream::FuturesUnordered, FutureExt, TryStreamExt};
use node_comm::node_traits::NodeInterface;
use utils::tap_log::TapLog;
use wallet::{
    account::{transaction_list::TransactionList, DelegationData, PoolData, TxInfo},
    wallet::WalletPoolsFilter,
};
use wallet_types::{
    account_info::StandaloneAddresses,
    utxo_types::{UtxoStates, UtxoTypes},
    wallet_tx::TxData,
    with_locked::WithLocked,
    Currency, KeyPurpose, KeychainUsageState,
};

use crate::{
    runtime_wallet::RuntimeWallet,
    types::{AccountStandaloneKeyDetails, Balances, CreatedBlockInfo},
    ControllerError,
};

pub struct ReadOnlyController<'a, T, B: storage::Backend + 'static> {
    wallet: &'a RuntimeWallet<B>,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    account_index: U31,
}

/// A Map between the derived child number and the Address with whether it is marked as used or not
type MapAddressWithUsage<T> = BTreeMap<ChildNumber, (Address<T>, bool)>;

pub struct AddressInfo {
    pub address: Address<Destination>,
    pub child_number: ChildNumber,
    pub purpose: KeyPurpose,
    pub used: bool,
    pub coins: Amount,
}

impl<'a, T, B> ReadOnlyController<'a, T, B>
where
    T: NodeInterface,
    B: storage::BackendWithSendableTransactions + 'static,
{
    pub fn new(
        wallet: &'a RuntimeWallet<B>,
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

    pub fn account_extended_public_key(
        &mut self,
    ) -> Result<&ExtendedPublicKey, ControllerError<T>> {
        self.wallet
            .account_extended_public_key(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_balance(
        &self,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<T>> {
        self.wallet
            .get_balance(self.account_index, utxo_states, with_locked)
            .map_err(ControllerError::WalletError)
    }

    pub async fn get_decimal_balance(
        &self,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Balances, ControllerError<T>> {
        let balances = self.get_balance(utxo_states, with_locked)?;
        super::into_balances(&self.rpc_client, self.chain_config, balances).await
    }

    pub fn get_multisig_utxos(
        &self,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ControllerError<T>> {
        self.wallet
            .get_multisig_utxos(self.account_index, utxo_types, utxo_states, with_locked)
            .map(|utxos| utxos.into_iter().collect())
            .map_err(ControllerError::WalletError)
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

    pub fn mainchain_transactions(
        &self,
        destination: Option<Destination>,
        limit: usize,
    ) -> Result<Vec<TxInfo>, ControllerError<T>> {
        self.wallet
            .mainchain_transactions(self.account_index, destination, limit)
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
        key_purpose: KeyPurpose,
    ) -> Result<BTreeMap<ChildNumber, Address<Destination>>, ControllerError<T>> {
        self.wallet
            .get_all_issued_addresses(self.account_index, key_purpose)
            .map_err(ControllerError::WalletError)
    }

    fn get_address_coin_balances(
        &self,
    ) -> Result<BTreeMap<Destination, Amount>, ControllerError<T>> {
        self.wallet
            .get_address_coin_balances(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_all_issued_vrf_public_keys(
        &self,
    ) -> Result<MapAddressWithUsage<VRFPublicKey>, ControllerError<T>> {
        self.wallet
            .get_all_issued_vrf_public_keys(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_legacy_vrf_public_key(&self) -> Result<Address<VRFPublicKey>, ControllerError<T>> {
        self.wallet
            .get_legacy_vrf_public_key(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_addresses_usage(
        &self,
        key_purpose: KeyPurpose,
    ) -> Result<&'a KeychainUsageState, ControllerError<T>> {
        self.wallet
            .get_addresses_usage(self.account_index, key_purpose)
            .map_err(ControllerError::WalletError)
    }

    /// Get all addresses with usage information and coin balances.
    /// The `used` boolean field is true if the address is used, false if otherwise.
    /// Note that the usage statistics follow strictly the rules of the wallet. For example,
    /// the initial wallet only stored information about the last used address, so the usage
    /// of all addresses after the first unused address will have the result `false`.
    pub fn get_addresses_with_usage(
        &self,
        include_change_addresses: bool,
    ) -> Result<Vec<AddressInfo>, ControllerError<T>> {
        let balances = self.get_address_coin_balances()?;

        let get_addresses = |key_purpose| -> Result<_, ControllerError<T>> {
            let addresses = self.get_all_issued_addresses(key_purpose)?;
            let usage = self.get_addresses_usage(key_purpose)?;
            let balances = &balances;

            Ok(addresses.into_iter().map(move |(child_number, address)| {
                let coins = balances.get(address.as_object()).copied().unwrap_or(Amount::ZERO);
                let used = usage.last_used().is_some_and(|used| used >= child_number.get_index());
                AddressInfo {
                    address,
                    child_number,
                    coins,
                    used,
                    purpose: key_purpose,
                }
            }))
        };

        let result = if include_change_addresses {
            get_addresses(KeyPurpose::ReceiveFunds)?
                .chain(get_addresses(KeyPurpose::Change)?)
                .collect()
        } else {
            get_addresses(KeyPurpose::ReceiveFunds)?.collect()
        };

        Ok(result)
    }

    /// Get all standalone addresses with their labels
    pub fn get_standalone_addresses(&self) -> Result<StandaloneAddresses, ControllerError<T>> {
        self.wallet
            .get_all_standalone_addresses(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    /// Get all standalone addresses with their labels and balances
    pub async fn get_standalone_address_details(
        &self,
        address: Destination,
    ) -> Result<AccountStandaloneKeyDetails, ControllerError<T>> {
        let (address, balances, details) = self
            .wallet
            .get_all_standalone_address_details(self.account_index, address)
            .map_err(ControllerError::WalletError)?;

        let balances = super::into_balances(&self.rpc_client, self.chain_config, balances).await?;

        Ok(AccountStandaloneKeyDetails {
            address,
            balances,
            details,
        })
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

    /// Get all pools owned by this account that can be used for staking
    pub async fn get_staking_pools(
        &self,
    ) -> Result<Vec<(PoolId, PoolData, Amount, Amount)>, ControllerError<T>> {
        self.get_pools(WalletPoolsFilter::Stake).await
    }

    /// Get all pools that can be decommissioned by this account
    pub async fn get_pools_for_decommission(
        &self,
    ) -> Result<Vec<(PoolId, PoolData, Amount, Amount)>, ControllerError<T>> {
        self.get_pools(WalletPoolsFilter::Decommission).await
    }

    async fn get_pools(
        &self,
        filter: WalletPoolsFilter,
    ) -> Result<Vec<(PoolId, PoolData, Amount, Amount)>, ControllerError<T>> {
        let pools = self
            .wallet
            .get_pool_ids(self.account_index, filter)
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
    ) -> Result<(PoolId, PoolData, Amount, Amount), ControllerError<T>> {
        let balance = self
            .rpc_client
            .get_stake_pool_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)
            .and_then(|balance| {
                balance.ok_or(ControllerError::SyncError(format!(
                    "Pool id {} from wallet not found in node",
                    Address::new(self.chain_config, pool_id)?
                )))
            })
            .log_err()?;

        self.rpc_client
            .get_staker_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)
            .and_then(|balance| {
                balance.ok_or(ControllerError::SyncError(format!(
                    "Pool id {} from wallet not found in node",
                    Address::new(self.chain_config, pool_id)?
                )))
            })
            .map(|pledge| (pool_id, pool_data, balance, pledge))
            .log_err()
    }

    pub async fn get_delegations(
        &self,
    ) -> Result<Vec<(DelegationId, PoolId, Amount)>, ControllerError<T>> {
        let tasks: FuturesUnordered<_> = self
            .wallet
            .get_delegations(self.account_index)
            .map_err(ControllerError::WalletError)?
            .map(|(delegation_id, delegation_data)| {
                self.get_delegation_share(delegation_data, *delegation_id).map(|res| {
                    res.map(|opt| {
                        opt.map(|(delegation_id, amount)| {
                            (delegation_id, delegation_data.pool_id, amount)
                        })
                    })
                })
            })
            .collect();

        let delegations = tasks.try_collect::<Vec<_>>().await?.into_iter().flatten().collect();

        Ok(delegations)
    }

    pub fn get_created_blocks(&self) -> Result<Vec<CreatedBlockInfo>, ControllerError<T>> {
        self.wallet
            .get_created_blocks(self.account_index)
            .map_err(ControllerError::WalletError)
            .map(|blocks| {
                blocks
                    .into_iter()
                    .map(|(height, id, pool_id)| {
                        let pool_id =
                            Address::new(self.chain_config, pool_id).expect("addressable");

                        CreatedBlockInfo {
                            height,
                            id,
                            pool_id: pool_id.to_string(),
                        }
                    })
                    .collect()
            })
    }

    async fn get_delegation_share(
        &self,
        delegation_data: &DelegationData,
        delegation_id: DelegationId,
    ) -> Result<Option<(DelegationId, Amount)>, ControllerError<T>> {
        if delegation_data.not_staked_yet {
            return Ok(Some((delegation_id, Amount::ZERO)));
        }

        self.rpc_client
            .get_delegation_share(delegation_data.pool_id, delegation_id)
            .await
            .map_err(ControllerError::NodeCallError)
            // If the balance is not found, it means that the delegation has been deleted from
            // chainstate due to the pool being decommissioned and the delegation's balance being 0
            .map(|opt_balance| opt_balance.map(|balance| (delegation_id, balance)))
            .log_err()
    }
}
