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

use crate::wallet_rpc_traits::ColdWalletInterface;

use super::{ClientWalletRpc, WalletRpcError};

use chainstate::ChainInfo;
use common::{
    chain::{Block, SignedTransaction, Transaction, UtxoOutPoint},
    primitives::{DecimalAmount, Id},
};
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress,
    socket_address::SocketAddress,
};
use serialization::hex_encoded::HexEncoded;
use wallet_controller::{types::Balances, ConnectedPeer, ControllerConfig, UtxoStates, UtxoTypes};
use wallet_rpc_lib::{
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, BlockInfo, DelegationInfo, EmptyArgs,
        NewAccountInfo, NewDelegation, NewTransaction, NftMetadata, NodeVersion, PoolInfo,
        PublicKeyInfo, RpcTokenId, SeedPhrase, StakePoolBalance, StakingStatus, TokenMetadata,
        TransactionOptions, TxOptionsOverrides, VrfPublicKeyInfo,
    },
    WalletRpcClient,
};
use wallet_types::with_locked::WithLocked;

#[async_trait::async_trait]
impl ColdWalletInterface for ClientWalletRpc {
    type Error = WalletRpcError;

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        WalletRpcClient::shutdown(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::create_wallet(&self.http_client, path, store_seed_phrase, mnemonic)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn open_wallet(&self, path: String, password: Option<String>) -> Result<(), Self::Error> {
        WalletRpcClient::open_wallet(&self.http_client, path, password)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn close_wallet(&self) -> Result<(), Self::Error> {
        WalletRpcClient::close_wallet(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        WalletRpcClient::sync(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn rescan(&self) -> Result<(), Self::Error> {
        WalletRpcClient::rescan(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_seed_phrase(&self) -> Result<SeedPhrase, Self::Error> {
        WalletRpcClient::get_seed_phrase(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn purge_seed_phrase(&self) -> Result<SeedPhrase, Self::Error> {
        WalletRpcClient::purge_seed_phrase(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::set_lookahead_size(
            &self.http_client,
            lookahead_size,
            i_know_what_i_am_doing,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error> {
        WalletRpcClient::encrypt_private_keys(&self.http_client, password)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error> {
        WalletRpcClient::remove_private_key_encryption(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error> {
        WalletRpcClient::unlock_private_keys(&self.http_client, password)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error> {
        WalletRpcClient::lock_private_key_encryption(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn best_block(&self) -> Result<BlockInfo, Self::Error> {
        WalletRpcClient::best_block(&self.http_client, EmptyArgs {})
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error> {
        WalletRpcClient::create_account(&self.http_client, name, EmptyArgs {})
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_issued_addresses(
        &self,
        options: AccountIndexArg,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error> {
        WalletRpcClient::get_issued_addresses(&self.http_client, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_address(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<AddressInfo, Self::Error> {
        WalletRpcClient::issue_address(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn reveal_public_key(
        &self,
        account_index: AccountIndexArg,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error> {
        WalletRpcClient::reveal_public_key(&self.http_client, account_index, address)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        _utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error> {
        WalletRpcClient::get_balance(&self.http_client, account_index, Some(with_locked))
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_utxos(
        &self,
        account_index: AccountIndexArg,
        _utxo_types: UtxoTypes,
        _utxo_states: UtxoStates,
        _with_locked: WithLocked,
    ) -> Result<Vec<serde_json::Value>, Self::Error> {
        WalletRpcClient::get_utxos(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> Result<NewTransaction, Self::Error> {
        WalletRpcClient::submit_raw_transaction(&self.http_client, tx, do_not_store, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        _selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::send_coins(&self.http_client, account_index, address, amount, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::create_stake_pool(
            &self.http_client,
            account_index,
            amount,
            cost_per_block,
            margin_ratio_per_thousand,
            decommission_address,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::decommission_stake_pool(
            &self.http_client,
            account_index,
            pool_id,
            output_address,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegation, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::create_delegation(
            &self.http_client,
            account_index,
            address,
            pool_id,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::delegate_staking(
            &self.http_client,
            account_index,
            amount,
            delegation_id,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn withdraw_from_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::withdraw_from_delegation(
            &self.http_client,
            account_index,
            address,
            amount,
            delegation_id,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn start_staking(&self, account_index: AccountIndexArg) -> Result<(), Self::Error> {
        WalletRpcClient::start_staking(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn stop_staking(&self, account_index: AccountIndexArg) -> Result<(), Self::Error> {
        WalletRpcClient::stop_staking(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn staking_status(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<StakingStatus, Self::Error> {
        WalletRpcClient::staking_status(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_pool_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<PoolInfo>, Self::Error> {
        WalletRpcClient::list_pool_ids(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error> {
        WalletRpcClient::stake_pool_balance(&self.http_client, pool_id)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<DelegationInfo>, Self::Error> {
        WalletRpcClient::list_delegation_ids(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<BlockInfo>, Self::Error> {
        WalletRpcClient::list_created_blocks_ids(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn new_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<VrfPublicKeyInfo, Self::Error> {
        WalletRpcClient::new_vrf_public_key(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error> {
        WalletRpcClient::get_vrf_public_key(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_new_nft(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::issue_new_nft(
            &self.http_client,
            account_index,
            destination_address,
            metadata,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_new_token(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::issue_new_token(
            &self.http_client,
            account_index,
            destination_address,
            metadata,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn change_token_authority(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::change_token_authority(
            &self.http_client,
            account_index,
            token_id,
            address,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn mint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::mint_tokens(
            &self.http_client,
            account_index,
            token_id,
            address,
            amount,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn unmint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::unmint_tokens(&self.http_client, account_index, token_id, amount, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn lock_token_supply(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::lock_token_supply(&self.http_client, account_index, token_id, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn freeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::freeze_token(
            &self.http_client,
            account_index,
            token_id,
            is_unfreezable,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn unfreeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::unfreeze_token(&self.http_client, account_index, token_id, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn send_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::send_tokens(
            &self.http_client,
            account_index,
            token_id,
            address,
            amount,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn deposit_data(
        &self,
        account_index: AccountIndexArg,
        data: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions {
            in_top_x_mb: config.in_top_x_mb,
        };
        WalletRpcClient::deposit_data(&self.http_client, account_index, data, options)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_version(&self) -> Result<NodeVersion, Self::Error> {
        WalletRpcClient::node_version(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        WalletRpcClient::node_shutdown(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        WalletRpcClient::connect_to_peer(&self.http_client, address.to_string())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn disconnect_peer(&self, peer_id: u64) -> Result<(), Self::Error> {
        WalletRpcClient::disconnect_peer(&self.http_client, peer_id)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_banned(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        WalletRpcClient::list_banned(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::ban_address(&self.http_client, address, duration)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn unban_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        WalletRpcClient::unban_address(&self.http_client, address)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_discouraged(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        WalletRpcClient::list_discouraged(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn peer_count(&self) -> Result<usize, Self::Error> {
        WalletRpcClient::peer_count(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        WalletRpcClient::connected_peers(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn reserved_peers(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        WalletRpcClient::reserved_peers(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        WalletRpcClient::add_reserved_peer(&self.http_client, address.to_string())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        WalletRpcClient::remove_reserved_peer(&self.http_client, address.to_string())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> Result<(), Self::Error> {
        WalletRpcClient::submit_block(&self.http_client, block)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        WalletRpcClient::chainstate_info(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn abandon_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::abandon_transaction(
            &self.http_client,
            account_index,
            HexEncoded::new(transaction_id),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn list_pending_transactions(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<Id<Transaction>>, Self::Error> {
        WalletRpcClient::list_pending_transactions(&self.http_client, account_index)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error> {
        WalletRpcClient::get_transaction(
            &self.http_client,
            account_index,
            HexEncoded::new(transaction_id),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_raw_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        WalletRpcClient::get_raw_transaction(
            &self.http_client,
            account_index,
            HexEncoded::new(transaction_id),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        WalletRpcClient::get_raw_signed_transaction(
            &self.http_client,
            account_index,
            HexEncoded::new(transaction_id),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }
}
