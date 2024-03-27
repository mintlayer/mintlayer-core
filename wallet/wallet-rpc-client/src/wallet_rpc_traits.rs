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

use std::{num::NonZeroUsize, path::PathBuf};

use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction, TxOutput, UtxoOutPoint},
    primitives::{BlockHeight, DecimalAmount, Id},
};
use crypto::key::{hdkd::u31::U31, PrivateKey};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use serialization::hex_encoded::HexEncoded;
use utils_networking::IpOrSocketAddress;
use wallet::account::{PartiallySignedTransaction, TxInfo};
use wallet_controller::{
    types::{CreatedBlockInfo, InspectTransaction, SeedWithPassPhrase, WalletInfo},
    ConnectedPeer, ControllerConfig, UtxoState, UtxoType,
};
use wallet_rpc_lib::types::{
    AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, ComposedTransaction, CreatedWallet,
    DelegationInfo, LegacyVrfPublicKeyInfo, NewAccountInfo, NewDelegation, NewTransaction,
    NftMetadata, NodeVersion, PoolInfo, PublicKeyInfo, RpcTokenId, StakePoolBalance, StakingStatus,
    StandaloneAddress, StandaloneAddressWithDetails, TokenMetadata, TxOptionsOverrides,
    VrfPublicKeyInfo,
};
use wallet_types::with_locked::WithLocked;

pub enum PartialOrSignedTx {
    Partial(PartiallySignedTransaction),
    Signed(SignedTransaction),
}

#[async_trait::async_trait]
pub trait WalletInterface {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn exit(&mut self) -> Result<(), Self::Error>;

    async fn shutdown(&mut self) -> Result<(), Self::Error>;

    async fn version(&self) -> Result<String, Self::Error>;

    async fn rpc_completed(&self);

    async fn create_wallet(
        &self,
        path: PathBuf,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    ) -> Result<CreatedWallet, Self::Error>;

    async fn open_wallet(
        &self,
        path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
    ) -> Result<(), Self::Error>;

    async fn close_wallet(&self) -> Result<(), Self::Error>;

    async fn wallet_info(&self) -> Result<WalletInfo, Self::Error>;

    async fn sync(&self) -> Result<(), Self::Error>;

    async fn rescan(&self) -> Result<(), Self::Error>;

    async fn get_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error>;

    async fn purge_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error>;

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error>;

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error>;

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error>;

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error>;

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error>;

    async fn best_block(&self) -> Result<BlockInfo, Self::Error>;

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error>;

    async fn rename_account(
        &self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<NewAccountInfo, Self::Error>;

    async fn add_standalone_address(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error>;

    async fn add_standalone_private_key(
        &self,
        account_index: U31,
        private_key: HexEncoded<PrivateKey>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error>;

    async fn add_standalone_multisig(
        &self,
        account_index: U31,
        min_required_signatures: u8,
        public_keys: Vec<String>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<String, Self::Error>;

    async fn get_issued_addresses(
        &self,
        options: U31,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error>;

    async fn get_standalone_addresses(
        &self,
        account_index: U31,
    ) -> Result<Vec<StandaloneAddress>, Self::Error>;

    async fn get_standalone_address_details(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<StandaloneAddressWithDetails, Self::Error>;

    async fn issue_address(&self, account_index: U31) -> Result<AddressInfo, Self::Error>;

    async fn reveal_public_key(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error>;

    async fn get_balance(
        &self,
        account_index: U31,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error>;

    async fn get_multisig_utxos(
        &self,
        account_index: U31,
        utxo_types: Vec<UtxoType>,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Vec<serde_json::Value>, Self::Error>;

    async fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: Vec<UtxoType>,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Vec<serde_json::Value>, Self::Error>;

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> Result<NewTransaction, Self::Error>;

    async fn sign_challenge(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error>;

    async fn sign_challenge_hex(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error>;

    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error>;

    async fn verify_challenge_hex(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error>;

    async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        only_transaction: bool,
    ) -> Result<ComposedTransaction, Self::Error>;

    async fn send_coins(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn sweep_addresses(
        &self,
        account_index: U31,
        destination_address: String,
        from_addresses: Vec<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn sweep_delegation(
        &self,
        account_index: U31,
        destination_address: String,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn transaction_from_cold_input(
        &self,
        account_index: U31,
        address: String,
        amount_str: DecimalAmount,
        selected_utxo: UtxoOutPoint,
        change_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<ComposedTransaction, Self::Error>;

    async fn transaction_inspect(
        &self,
        transaction: String,
    ) -> Result<InspectTransaction, Self::Error>;

    async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<HexEncoded<PartiallySignedTransaction>, Self::Error>;

    async fn create_delegation(
        &self,
        account_index: U31,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegation, Self::Error>;

    async fn delegate_staking(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn withdraw_from_delegation(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn start_staking(&self, account_index: U31) -> Result<(), Self::Error>;

    async fn stop_staking(&self, account_index: U31) -> Result<(), Self::Error>;

    async fn staking_status(&self, account_index: U31) -> Result<StakingStatus, Self::Error>;

    async fn list_staking_pools(&self, account_index: U31) -> Result<Vec<PoolInfo>, Self::Error>;

    async fn list_pools_for_decommission(
        &self,
        account_index: U31,
    ) -> Result<Vec<PoolInfo>, Self::Error>;

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error>;

    async fn list_delegation_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<DelegationInfo>, Self::Error>;

    async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<CreatedBlockInfo>, Self::Error>;

    async fn new_vrf_public_key(&self, account_index: U31)
        -> Result<VrfPublicKeyInfo, Self::Error>;

    async fn get_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error>;

    async fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<LegacyVrfPublicKeyInfo, Self::Error>;

    async fn issue_new_nft(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error>;

    async fn issue_new_token(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error>;

    async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn freeze_token(
        &self,
        account_index: U31,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn send_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn deposit_data(
        &self,
        account_index: U31,
        data: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error>;

    async fn node_version(&self) -> Result<NodeVersion, Self::Error>;

    async fn node_shutdown(&self) -> Result<(), Self::Error>;

    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error>;

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error>;

    async fn disconnect_peer(&self, peer_id: PeerId) -> Result<(), Self::Error>;

    async fn list_banned(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error>;

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> Result<(), Self::Error>;

    async fn unban_address(&self, address: BannableAddress) -> Result<(), Self::Error>;

    async fn list_discouraged(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error>;

    async fn peer_count(&self) -> Result<usize, Self::Error>;

    async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error>;

    async fn reserved_peers(&self) -> Result<Vec<SocketAddress>, Self::Error>;

    async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error>;

    async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error>;

    async fn submit_block(&self, block: HexEncoded<Block>) -> Result<(), Self::Error>;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error>;

    async fn abandon_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error>;

    async fn list_pending_transactions(
        &self,
        account_index: U31,
    ) -> Result<Vec<Id<Transaction>>, Self::Error>;

    async fn list_transactions_by_address(
        &self,
        account_index: U31,
        address: Option<String>,
        limit: usize,
    ) -> Result<Vec<TxInfo>, Self::Error>;

    async fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error>;

    async fn get_raw_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error>;

    async fn get_raw_signed_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error>;

    async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: String,
        config: ControllerConfig,
    ) -> Result<PartialOrSignedTx, Self::Error>;

    async fn node_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error>;

    async fn node_best_block_height(&self) -> Result<BlockHeight, Self::Error>;

    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error>;

    async fn node_generate_block(
        &self,
        account_index: U31,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> Result<(), Self::Error>;

    async fn node_generate_blocks(
        &self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), Self::Error>;

    async fn node_block(&self, block_id: String) -> Result<Option<String>, Self::Error>;

    async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error>;
}
