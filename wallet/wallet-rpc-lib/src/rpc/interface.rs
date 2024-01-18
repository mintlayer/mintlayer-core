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

use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use p2p_types::bannable_address::BannableAddress;
use wallet_controller::ConnectedPeer;
use wallet_types::with_locked::WithLocked;

use crate::types::{
    AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DecimalAmount,
    DelegationInfo, EmptyArgs, HexEncoded, JsonValue, NewAccountInfo, NewDelegation, NftMetadata,
    NodeVersion, PoolInfo, PublicKeyInfo, RpcTokenId, SeedPhrase, StakePoolBalance, TokenMetadata,
    TransactionOptions, TxOptionsOverrides, VrfPublicKeyInfo,
};

#[rpc::rpc(server)]
trait WalletRpc {
    #[method(name = "shutdown")]
    async fn shutdown(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_create")]
    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> rpc::RpcResult<()>;

    #[method(name = "wallet_open")]
    async fn open_wallet(&self, path: String, password: Option<String>) -> rpc::RpcResult<()>;

    #[method(name = "wallet_close")]
    async fn close_wallet(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_sync")]
    async fn sync(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_rescan")]
    async fn rescan(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_show_seed_phrase")]
    async fn get_seed_phrase(&self) -> rpc::RpcResult<SeedPhrase>;

    #[method(name = "wallet_purge_seed_phrase")]
    async fn purge_seed_phrase(&self) -> rpc::RpcResult<SeedPhrase>;

    #[method(name = "wallet_set_lookahead_size")]
    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> rpc::RpcResult<()>;

    #[method(name = "wallet_encrypt_private_keys")]
    async fn encrypt_private_keys(&self, password: String) -> rpc::RpcResult<()>;

    #[method(name = "wallet_disable_private_keys_encryption")]
    async fn remove_private_key_encryption(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_unlock_private_keys")]
    async fn unlock_private_keys(&self, password: String) -> rpc::RpcResult<()>;

    #[method(name = "wallet_lock_private_keys")]
    async fn lock_private_key_encryption(&self) -> rpc::RpcResult<()>;

    #[method(name = "wallet_best_block")]
    async fn best_block(&self, options: EmptyArgs) -> rpc::RpcResult<BlockInfo>;

    #[method(name = "account_create")]
    async fn create_account(
        &self,
        name: Option<String>,
        options: EmptyArgs,
    ) -> rpc::RpcResult<NewAccountInfo>;

    #[method(name = "address_show")]
    async fn get_issued_addresses(
        &self,
        options: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>>;

    #[method(name = "address_new")]
    async fn issue_address(&self, account_index: AccountIndexArg) -> rpc::RpcResult<AddressInfo>;

    #[method(name = "address_new_public_key")]
    async fn issue_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<PublicKeyInfo>;

    #[method(name = "account_balance")]
    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances>;

    #[method(name = "account_utxos")]
    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<JsonValue>>;

    #[method(name = "node_submit_transaction")]
    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<()>;

    #[method(name = "address_send")]
    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "staking_create_pool")]
    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "staking_decommission_pool")]
    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "delegation_create")]
    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation>;

    #[method(name = "delegation_stake")]
    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "delegation_send_to_address")]
    async fn send_from_delegation_to_address(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "staking_start")]
    async fn start_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()>;

    #[method(name = "staking_stop")]
    async fn stop_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()>;

    #[method(name = "staking_list_pool_ids")]
    async fn list_pool_ids(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<PoolInfo>>;

    #[method(name = "staking_pool_balance")]
    async fn stake_pool_balance(&self, pool_id: String) -> rpc::RpcResult<StakePoolBalance>;

    #[method(name = "delegation_list_ids")]
    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>>;

    #[method(name = "staking_list_created_block_ids")]
    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<GenBlock>>>;

    #[method(name = "staking_show_vrf_public_keys")]
    async fn get_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<VrfPublicKeyInfo>>;

    #[method(name = "token_nft_issue_new")]
    async fn issue_new_nft(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: NftMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId>;

    #[method(name = "token_issue_new")]
    async fn issue_new_token(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: TokenMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId>;

    #[method(name = "token_change_authority")]
    async fn change_token_authority(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_mint")]
    async fn mint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_unmint")]
    async fn unmint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_lock_supply")]
    async fn lock_token_supply(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_freeze")]
    async fn freeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        is_unfreezable: bool,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_unfreeze")]
    async fn unfreeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "token_send")]
    async fn send_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "address_deposit_data")]
    async fn deposit_data(
        &self,
        account_index: AccountIndexArg,
        data: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<()>;

    #[method(name = "node_version")]
    async fn node_version(&self) -> rpc::RpcResult<NodeVersion>;

    #[method(name = "node_shutdown")]
    async fn node_shutdown(&self) -> rpc::RpcResult<()>;

    #[method(name = "node_connect_to_peer")]
    async fn connect_to_peer(&self, address: String) -> rpc::RpcResult<()>;

    #[method(name = "node_disconnect_peer")]
    async fn disconnect_peer(&self, peer_id: u64) -> rpc::RpcResult<()>;

    #[method(name = "node_list_banned_peers")]
    async fn list_banned(&self) -> rpc::RpcResult<Vec<BannableAddress>>;

    #[method(name = "node_ban_peer_address")]
    async fn ban_address(&self, address: BannableAddress) -> rpc::RpcResult<()>;

    #[method(name = "node_unban_peer_address")]
    async fn unban_address(&self, address: BannableAddress) -> rpc::RpcResult<()>;

    #[method(name = "node-peer-count")]
    async fn peer_count(&self) -> rpc::RpcResult<usize>;

    #[method(name = "node_list_connected_peers")]
    async fn connected_peers(&self) -> rpc::RpcResult<Vec<ConnectedPeer>>;

    #[method(name = "node_add_reserved_peer")]
    async fn add_reserved_peer(&self, address: String) -> rpc::RpcResult<()>;

    #[method(name = "node_remove_reserved_peer")]
    async fn remove_reserved_peer(&self, address: String) -> rpc::RpcResult<()>;

    #[method(name = "node_submit_block")]
    async fn submit_block(&self, block: HexEncoded<Block>) -> rpc::RpcResult<()>;

    #[method(name = "node_chainstate_info")]
    async fn chainstate_info(&self) -> rpc::RpcResult<ChainInfo>;

    #[method(name = "node_best_block_id")]
    async fn node_best_block_id(&self) -> rpc::RpcResult<Id<GenBlock>>;

    #[method(name = "node_best_block_height")]
    async fn node_best_block_height(&self) -> rpc::RpcResult<BlockHeight>;

    #[method(name = "node_block_id")]
    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> rpc::RpcResult<Option<Id<GenBlock>>>;

    #[method(name = "node_get_block")]
    async fn node_block(&self, block_id: String) -> rpc::RpcResult<Option<Block>>;

    #[method(name = "node_generate_block")]
    async fn node_generate_block(
        &self,
        account_index: AccountIndexArg,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> rpc::RpcResult<()>;

    #[method(name = "node_generate_blocks")]
    async fn node_generate_blocks(
        &self,
        account_index: AccountIndexArg,
        block_count: u32,
    ) -> rpc::RpcResult<()>;

    #[method(name = "transaction_abandon")]
    async fn abandon_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<()>;

    #[method(name = "transaction_list_pending")]
    async fn list_pending_transactions(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<Transaction>>>;

    #[method(name = "transaction_get")]
    async fn get_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<serde_json::Value>;

    #[method(name = "transaction_get_raw")]
    async fn get_raw_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<String>;

    #[method(name = "transaction_get_signed_raw")]
    async fn get_raw_signed_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<String>;
}
