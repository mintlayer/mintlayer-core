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

use std::collections::BTreeSet;

use common::{
    address::Address,
    chain::{
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        ChainConfig, DelegationId, Destination, PoolId, SignedTransaction, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Id},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use logging::log;
use node_comm::node_traits::NodeInterface;
use wallet::{
    send_request::{
        make_address_output, make_address_output_token, make_create_delegation_output,
        StakePoolDataArguments,
    },
    wallet_events::WalletEvents,
    DefaultWallet, WalletError,
};

use crate::{ControllerConfig, ControllerError};

pub struct SyncedController<'a, T, W> {
    wallet: &'a mut DefaultWallet,
    rpc_client: T,
    chain_config: &'a ChainConfig,
    wallet_events: &'a W,
    staking_started: &'a mut BTreeSet<U31>,
    account_index: U31,
    config: ControllerConfig,
}

impl<'a, T: NodeInterface, W: WalletEvents> SyncedController<'a, T, W> {
    pub fn new(
        wallet: &'a mut DefaultWallet,
        rpc_client: T,
        chain_config: &'a ChainConfig,
        wallet_events: &'a W,
        staking_started: &'a mut BTreeSet<U31>,
        account_index: U31,
        config: ControllerConfig,
    ) -> Self {
        Self {
            wallet,
            rpc_client,
            chain_config,
            wallet_events,
            staking_started,
            account_index,
            config,
        }
    }

    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .abandon_transaction(self.account_index, tx_id)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_address(
        &mut self,
    ) -> Result<(ChildNumber, Address<Destination>), ControllerError<T>> {
        self.wallet
            .get_new_address(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_public_key(&mut self) -> Result<PublicKey, ControllerError<T>> {
        self.wallet
            .get_new_public_key(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_vrf_public_key(&mut self) -> Result<VRFPublicKey, ControllerError<T>> {
        self.wallet
            .get_vrf_public_key(self.account_index)
            .map_err(ControllerError::WalletError)
    }

    pub async fn issue_new_token(
        &mut self,
        address: Address<Destination>,
        token_ticker: Vec<u8>,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
        token_total_supply: TokenTotalSupply,
        is_freezable: IsTokenFreezable,
    ) -> Result<TokenId, ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;
        let destination = address.decode_object(self.chain_config.as_ref())?;
        let (token_id, tx) = self
            .wallet
            .issue_new_token(
                self.account_index,
                TokenIssuance::V1(TokenIssuanceV1 {
                    token_ticker,
                    number_of_decimals,
                    metadata_uri,
                    total_supply: token_total_supply,
                    authority: destination,
                    is_freezable,
                }),
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await?;

        Ok(token_id)
    }

    pub async fn issue_new_nft(
        &mut self,
        address: Address<Destination>,
        metadata: Metadata,
    ) -> Result<TokenId, ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;
        let (token_id, tx) = self
            .wallet
            .issue_new_nft(
                self.account_index,
                address,
                metadata,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await?;

        Ok(token_id)
    }

    pub async fn mint_tokens(
        &mut self,
        token_id: TokenId,
        amount: Amount,
        address: Address<Destination>,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .mint_tokens(
                self.account_index,
                token_id,
                amount,
                address,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn unmint_tokens(
        &mut self,
        token_id: TokenId,
        amount: Amount,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .unmint_tokens(
                self.account_index,
                token_id,
                amount,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn lock_token_supply(&mut self, token_id: TokenId) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .lock_token_supply(
                self.account_index,
                token_id,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    /// After freezing a token all operations (transfer, mint, unmint...)
    /// on that token are forbidden until it is unfrozen
    pub async fn freeze_token(
        &mut self,
        token_id: TokenId,
        is_token_unfreezable: IsTokenUnfreezable,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .freeze_token(
                self.account_index,
                token_id,
                is_token_unfreezable,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    /// After unfreezing a token all operations on that token are again permitted
    pub async fn unfreeze_token(&mut self, token_id: TokenId) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .unfreeze_token(
                self.account_index,
                token_id,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn send_to_address(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        selected_utxos: Vec<UtxoOutPoint>,
    ) -> Result<(), ControllerError<T>> {
        let output = make_address_output(self.chain_config, address, amount)
            .map_err(ControllerError::WalletError)?;
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .create_transaction_to_addresses(
                self.account_index,
                [output],
                selected_utxos,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn create_delegation(
        &mut self,
        address: Address<Destination>,
        pool_id: PoolId,
    ) -> Result<DelegationId, ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;
        let output = make_create_delegation_output(self.chain_config, address, pool_id)
            .map_err(ControllerError::WalletError)?;
        let (delegation_id, tx) = self
            .wallet
            .create_delegation(
                self.account_index,
                vec![output],
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await?;

        Ok(delegation_id)
    }

    pub async fn delegate_staking(
        &mut self,
        amount: Amount,
        delegation_id: DelegationId,
    ) -> Result<(), ControllerError<T>> {
        let output = TxOutput::DelegateStaking(amount, delegation_id);

        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .create_transaction_to_addresses(
                self.account_index,
                [output],
                [],
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn send_to_address_from_delegation(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, _) = self.get_current_and_consolidation_fee_rate().await?;

        let pool_id = self
            .wallet
            .get_delegation(self.account_index, delegation_id)
            .map_err(ControllerError::WalletError)?
            .pool_id;

        let delegation_share = self
            .rpc_client
            .get_delegation_share(pool_id, delegation_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(
                WalletError::DelegationNotFound(delegation_id),
            ))?;

        let tx = self
            .wallet
            .create_transaction_to_addresses_from_delegation(
                self.account_index,
                address,
                amount,
                delegation_id,
                delegation_share,
                current_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn send_tokens_to_address(
        &mut self,
        token_id: TokenId,
        address: Address<Destination>,
        amount: Amount,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let output = make_address_output_token(self.chain_config, address, amount, token_id)
            .map_err(ControllerError::WalletError)?;
        let tx = self
            .wallet
            .create_transaction_to_addresses(
                self.account_index,
                [output],
                [],
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn create_stake_pool_tx(
        &mut self,
        amount: Amount,
        decommission_key: Option<PublicKey>,
        margin_ratio_per_thousand: PerThousand,
        cost_per_block: Amount,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, consolidate_fee_rate) =
            self.get_current_and_consolidation_fee_rate().await?;

        let tx = self
            .wallet
            .create_stake_pool_tx(
                self.account_index,
                decommission_key,
                current_fee_rate,
                consolidate_fee_rate,
                StakePoolDataArguments {
                    amount,
                    margin_ratio_per_thousand,
                    cost_per_block,
                },
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn decommission_stake_pool(
        &mut self,
        pool_id: PoolId,
    ) -> Result<(), ControllerError<T>> {
        let (current_fee_rate, _) = self.get_current_and_consolidation_fee_rate().await?;

        let staker_balance = self
            .rpc_client
            .get_stake_pool_pledge(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownPoolId(
                pool_id,
            )))?;

        let tx = self
            .wallet
            .decommission_stake_pool(
                self.account_index,
                pool_id,
                staker_balance,
                current_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub fn start_staking(&mut self) -> Result<(), ControllerError<T>> {
        utils::ensure!(!self.wallet.is_locked(), ControllerError::WalletIsLocked);
        // Make sure that account_index is valid and that pools exist
        let pool_ids = self
            .wallet
            .get_pool_ids(self.account_index)
            .map_err(ControllerError::WalletError)?;
        utils::ensure!(!pool_ids.is_empty(), ControllerError::NoStakingPool);
        log::info!("Start staking, account_index: {}", self.account_index);
        self.staking_started.insert(self.account_index);
        Ok(())
    }

    async fn get_current_and_consolidation_fee_rate(
        &mut self,
    ) -> Result<(mempool::FeeRate, mempool::FeeRate), ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(self.config.in_top_x_mb)
            .await
            .map_err(ControllerError::NodeCallError)?;
        let consolidate_fee_rate = current_fee_rate;
        Ok((current_fee_rate, consolidate_fee_rate))
    }

    /// Broadcast a singed transaction to the mempool and update the wallets state if the
    /// transaction has been added to the mempool
    async fn broadcast_to_mempool(
        &mut self,
        tx: SignedTransaction,
    ) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)?;

        self.wallet
            .add_unconfirmed_tx(tx, self.wallet_events)
            .map_err(ControllerError::WalletError)?;

        Ok(())
    }
}
