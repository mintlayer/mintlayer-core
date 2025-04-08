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

use std::{collections::BTreeMap, future::pending, num::NonZeroUsize, path::PathBuf, str::FromStr};

use crate::wallet_rpc_traits::{
    FromRpcInput, PartialOrSignedTx, SignRawTransactionResult, WalletInterface,
};

use super::{ClientWalletRpc, WalletRpcError};

use chainstate::{rpc::RpcOutputValueIn, ChainInfo};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, Block, GenBlock, SignedTransaction,
        SignedTransactionIntent, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, DecimalAmount, Id},
};
use crypto::key::{hdkd::u31::U31, PrivateKey};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use rpc::types::RpcHexString;
use serialization::hex_encoded::HexEncoded;
use serialization::DecodeAll;
use utils_networking::IpOrSocketAddress;
use wallet::account::TxInfo;
use wallet_controller::{
    types::{
        Balances, CreatedBlockInfo, GenericTokenTransfer, SeedWithPassPhrase, WalletInfo,
        WalletTypeArgs,
    },
    ConnectedPeer, ControllerConfig, UtxoState, UtxoType,
};
use wallet_rpc_lib::{
    types::{
        AddressInfo, AddressWithUsageInfo, BlockInfo, ComposedTransaction, CreatedWallet,
        DelegationInfo, HardwareWalletType, LegacyVrfPublicKeyInfo, NewAccountInfo, NewDelegation,
        NewOrder, NewTransaction, NftMetadata, NodeVersion, OpenedWallet, PoolInfo, PublicKeyInfo,
        RpcHashedTimelockContract, RpcInspectTransaction, RpcStandaloneAddresses, RpcTokenId,
        SendTokensFromMultisigAddressResult, StakePoolBalance, StakingStatus,
        StandaloneAddressWithDetails, TokenMetadata, TransactionOptions, TxOptionsOverrides,
        UtxoInfo, VrfPublicKeyInfo,
    },
    ColdWalletRpcClient, WalletRpcClient,
};
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, with_locked::WithLocked,
};

#[async_trait::async_trait]
impl WalletInterface for ClientWalletRpc {
    type Error = WalletRpcError;

    async fn exit(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        ColdWalletRpcClient::shutdown(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn version(&self) -> Result<String, Self::Error> {
        ColdWalletRpcClient::version(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn rpc_completed(&self) {
        pending().await
    }

    async fn create_wallet(
        &self,
        path: PathBuf,
        wallet_args: WalletTypeArgs,
    ) -> Result<CreatedWallet, Self::Error> {
        let (mnemonic, passphrase, store_seed_phrase, hardware_wallet) = match wallet_args {
            WalletTypeArgs::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => (mnemonic, passphrase, store_seed_phrase.should_save(), None),
            #[cfg(feature = "trezor")]
            WalletTypeArgs::Trezor { device_id } => (
                None,
                None,
                false,
                Some(HardwareWalletType::Trezor { device_id }),
            ),
        };

        ColdWalletRpcClient::create_wallet(
            &self.http_client,
            path.to_string_lossy().to_string(),
            store_seed_phrase,
            mnemonic,
            passphrase,
            hardware_wallet,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn recover_wallet(
        &self,
        path: PathBuf,
        wallet_args: WalletTypeArgs,
    ) -> Result<CreatedWallet, Self::Error> {
        let (mnemonic, passphrase, store_seed_phrase, hardware_wallet) = match wallet_args {
            WalletTypeArgs::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => (mnemonic, passphrase, store_seed_phrase.should_save(), None),
            #[cfg(feature = "trezor")]
            WalletTypeArgs::Trezor { device_id } => (
                None,
                None,
                false,
                Some(HardwareWalletType::Trezor { device_id }),
            ),
        };

        ColdWalletRpcClient::recover_wallet(
            &self.http_client,
            path.to_string_lossy().to_string(),
            store_seed_phrase,
            mnemonic,
            passphrase,
            hardware_wallet,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn open_wallet(
        &self,
        path: PathBuf,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
        hardware_wallet: Option<HardwareWalletType>,
    ) -> Result<OpenedWallet, Self::Error> {
        ColdWalletRpcClient::open_wallet(
            &self.http_client,
            path.to_string_lossy().to_string(),
            password,
            force_migrate_wallet_type,
            hardware_wallet,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn close_wallet(&self) -> Result<(), Self::Error> {
        ColdWalletRpcClient::close_wallet(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn wallet_info(&self) -> Result<WalletInfo, Self::Error> {
        ColdWalletRpcClient::wallet_info(&self.http_client)
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

    async fn get_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        ColdWalletRpcClient::get_seed_phrase(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn purge_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, Self::Error> {
        ColdWalletRpcClient::purge_seed_phrase(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error> {
        ColdWalletRpcClient::set_lookahead_size(
            &self.http_client,
            lookahead_size,
            i_know_what_i_am_doing,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error> {
        ColdWalletRpcClient::encrypt_private_keys(&self.http_client, password)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error> {
        ColdWalletRpcClient::remove_private_key_encryption(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error> {
        ColdWalletRpcClient::unlock_private_keys(&self.http_client, password)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error> {
        ColdWalletRpcClient::lock_private_key_encryption(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn best_block(&self) -> Result<BlockInfo, Self::Error> {
        WalletRpcClient::best_block(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error> {
        WalletRpcClient::create_account(&self.http_client, name)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn rename_account(
        &self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<NewAccountInfo, Self::Error> {
        WalletRpcClient::rename_account(&self.http_client, account_index.into(), name)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn standalone_address_label_rename(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::standalone_address_label_rename(
            &self.http_client,
            account_index.into(),
            address.into(),
            label,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn add_standalone_address(
        &self,
        account_index: U31,
        address: String,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::add_standalone_address(
            &self.http_client,
            account_index.into(),
            address.into(),
            label,
            Some(no_rescan),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn add_standalone_private_key(
        &self,
        account_index: U31,
        private_key: HexEncoded<PrivateKey>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::add_standalone_private_key(
            &self.http_client,
            account_index.into(),
            private_key,
            label,
            Some(no_rescan),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn add_standalone_multisig(
        &self,
        account_index: U31,
        min_required_signatures: u8,
        public_keys: Vec<String>,
        label: Option<String>,
        no_rescan: bool,
    ) -> Result<String, Self::Error> {
        WalletRpcClient::add_standalone_multisig(
            &self.http_client,
            account_index.into(),
            min_required_signatures,
            public_keys.into_iter().map(Into::into).collect(),
            label,
            Some(no_rescan),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_issued_addresses(
        &self,
        account_index: U31,
        include_change_addresses: bool,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error> {
        ColdWalletRpcClient::get_issued_addresses(
            &self.http_client,
            account_index.into(),
            include_change_addresses,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_standalone_addresses(
        &self,
        account_index: U31,
    ) -> Result<RpcStandaloneAddresses, Self::Error> {
        ColdWalletRpcClient::get_standalone_addresses(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_standalone_address_details(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<StandaloneAddressWithDetails, Self::Error> {
        ColdWalletRpcClient::get_standalone_address_details(
            &self.http_client,
            account_index.into(),
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_address(&self, account_index: U31) -> Result<AddressInfo, Self::Error> {
        ColdWalletRpcClient::issue_address(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn reveal_public_key(
        &self,
        account_index: U31,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error> {
        ColdWalletRpcClient::reveal_public_key(
            &self.http_client,
            account_index.into(),
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_balance(
        &self,
        account_index: U31,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error> {
        WalletRpcClient::get_balance(
            &self.http_client,
            account_index.into(),
            utxo_states.iter().map(Into::into).collect(),
            Some(with_locked),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_multisig_utxos(
        &self,
        account_index: U31,
        utxo_types: Vec<UtxoType>,
        utxo_states: Vec<UtxoState>,
        with_locked: WithLocked,
    ) -> Result<Vec<UtxoInfo>, Self::Error> {
        WalletRpcClient::get_multisig_utxos(
            &self.http_client,
            account_index.into(),
            utxo_types.iter().map(Into::into).collect(),
            utxo_states.iter().map(Into::into).collect(),
            Some(with_locked),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_utxos(
        &self,
        account_index: U31,
        _utxo_types: Vec<UtxoType>,
        _utxo_states: Vec<UtxoState>,
        _with_locked: WithLocked,
    ) -> Result<Vec<UtxoInfo>, Self::Error> {
        WalletRpcClient::get_utxos(&self.http_client, account_index.into())
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
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        let selected_utxos = selected_utxos.into_iter().map(Into::into).collect();
        WalletRpcClient::send_coins(
            &self.http_client,
            account_index.into(),
            address.into(),
            amount.into(),
            selected_utxos,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn sweep_addresses(
        &self,
        account_index: U31,
        destination_address: String,
        from_addresses: Vec<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        let all = from_addresses.is_empty();
        WalletRpcClient::sweep_addresses(
            &self.http_client,
            account_index.into(),
            destination_address.into(),
            from_addresses.into_iter().map(Into::into).collect(),
            Some(all),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn sweep_delegation(
        &self,
        account_index: U31,
        destination_address: String,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::sweep_delegation(
            &self.http_client,
            account_index.into(),
            destination_address.into(),
            delegation_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn transaction_from_cold_input(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        selected_utxo: UtxoOutPoint,
        change_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<ComposedTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::transaction_from_cold_input(
            &self.http_client,
            account_index.into(),
            address.into(),
            amount.into(),
            selected_utxo.into(),
            change_address.map(Into::into),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn transaction_inspect(
        &self,
        transaction: String,
    ) -> Result<RpcInspectTransaction, Self::Error> {
        WalletRpcClient::transaction_inspect(&self.http_client, transaction.parse()?)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn create_stake_pool(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        staker_address: Option<String>,
        vrf_public_key: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::create_stake_pool(
            &self.http_client,
            account_index.into(),
            amount.into(),
            cost_per_block.into(),
            margin_ratio_per_thousand,
            decommission_address.into(),
            staker_address.map(Into::into),
            vrf_public_key.map(Into::into),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn decommission_stake_pool(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::decommission_stake_pool(
            &self.http_client,
            account_index.into(),
            pool_id.into(),
            output_address.map(Into::into),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn decommission_stake_pool_request(
        &self,
        account_index: U31,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<HexEncoded<PartiallySignedTransaction>, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::decommission_stake_pool_request(
            &self.http_client,
            account_index.into(),
            pool_id.into(),
            output_address.map(Into::into),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn create_delegation(
        &self,
        account_index: U31,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegation, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::create_delegation(
            &self.http_client,
            account_index.into(),
            address.into(),
            pool_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn delegate_staking(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::delegate_staking(
            &self.http_client,
            account_index.into(),
            amount.into(),
            delegation_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn withdraw_from_delegation(
        &self,
        account_index: U31,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::withdraw_from_delegation(
            &self.http_client,
            account_index.into(),
            address.into(),
            amount.into(),
            delegation_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn start_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        WalletRpcClient::start_staking(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn stop_staking(&self, account_index: U31) -> Result<(), Self::Error> {
        WalletRpcClient::stop_staking(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn staking_status(&self, account_index: U31) -> Result<StakingStatus, Self::Error> {
        WalletRpcClient::staking_status(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_staking_pools(&self, account_index: U31) -> Result<Vec<PoolInfo>, Self::Error> {
        WalletRpcClient::list_pools(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_pools_for_decommission(
        &self,
        account_index: U31,
    ) -> Result<Vec<PoolInfo>, Self::Error> {
        WalletRpcClient::list_pools_for_decommission(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error> {
        WalletRpcClient::stake_pool_balance(&self.http_client, pool_id.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_delegation_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<DelegationInfo>, Self::Error> {
        WalletRpcClient::list_delegation_ids(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<CreatedBlockInfo>, Self::Error> {
        WalletRpcClient::list_created_blocks_ids(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn new_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<VrfPublicKeyInfo, Self::Error> {
        ColdWalletRpcClient::new_vrf_public_key(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error> {
        ColdWalletRpcClient::get_vrf_public_key(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_legacy_vrf_public_key(
        &self,
        account_index: U31,
    ) -> Result<LegacyVrfPublicKeyInfo, Self::Error> {
        ColdWalletRpcClient::get_legacy_vrf_public_key(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_new_nft(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::issue_new_nft(
            &self.http_client,
            account_index.into(),
            destination_address.into(),
            metadata,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn issue_new_token(
        &self,
        account_index: U31,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::issue_new_token(
            &self.http_client,
            account_index.into(),
            destination_address.into(),
            metadata,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn change_token_authority(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::change_token_authority(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            address.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn change_token_metadata_uri(
        &self,
        account_index: U31,
        token_id: String,
        metadata_uri: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::change_token_metadata_uri(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            RpcHexString::from_str(&metadata_uri)?,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn mint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::mint_tokens(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            address.into(),
            amount.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn unmint_tokens(
        &self,
        account_index: U31,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::unmint_tokens(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            amount.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn lock_token_supply(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::lock_token_supply(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn freeze_token(
        &self,
        account_index: U31,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::freeze_token(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            is_unfreezable,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn unfreeze_token(
        &self,
        account_index: U31,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::unfreeze_token(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn send_tokens(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::send_tokens(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            address.into(),
            amount.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn make_tx_for_sending_tokens_with_intent(
        &self,
        account_index: U31,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        intent: String,
        config: ControllerConfig,
    ) -> Result<
        (
            HexEncoded<SignedTransaction>,
            HexEncoded<SignedTransactionIntent>,
        ),
        Self::Error,
    > {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::make_tx_for_sending_tokens_with_intent(
            &self.http_client,
            account_index.into(),
            token_id.into(),
            address.into(),
            amount.into(),
            intent,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn make_tx_to_send_tokens_from_multisig_address(
        &self,
        account_index: U31,
        from_address: String,
        fee_change_address: Option<String>,
        outputs: Vec<GenericTokenTransfer>,
        config: ControllerConfig,
    ) -> Result<SendTokensFromMultisigAddressResult, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::make_tx_to_send_tokens_from_multisig_address(
            &self.http_client,
            account_index.into(),
            from_address.into(),
            fee_change_address.map(Into::into),
            outputs,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn deposit_data(
        &self,
        account_index: U31,
        data: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::deposit_data(
            &self.http_client,
            account_index.into(),
            data.parse()?,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn create_htlc_transaction(
        &self,
        account_index: U31,
        amount: DecimalAmount,
        token_id: Option<String>,
        htlc: RpcHashedTimelockContract,
        config: ControllerConfig,
    ) -> Result<HexEncoded<SignedTransaction>, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::create_htlc_transaction(
            &self.http_client,
            account_index.into(),
            amount.into(),
            token_id.map(|id| id.into()),
            htlc,
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn create_order(
        &self,
        account_index: U31,
        ask_token_id: Option<String>,
        ask_amount: DecimalAmount,
        give_token_id: Option<String>,
        give_amount: DecimalAmount,
        conclude_address: String,
        config: ControllerConfig,
    ) -> Result<NewOrder, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::create_order(
            &self.http_client,
            account_index.into(),
            RpcOutputValueIn::from_rpc_string_input(ask_token_id, ask_amount),
            RpcOutputValueIn::from_rpc_string_input(give_token_id, give_amount),
            conclude_address.into(),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn conclude_order(
        &self,
        account_index: U31,
        order_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::conclude_order(
            &self.http_client,
            account_index.into(),
            order_id.into(),
            output_address.map(|addr| addr.into()),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn fill_order(
        &self,
        account_index: U31,
        order_id: String,
        fill_amount_in_ask_currency: DecimalAmount,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::fill_order(
            &self.http_client,
            account_index.into(),
            order_id.into(),
            fill_amount_in_ask_currency.into(),
            output_address.map(|addr| addr.into()),
            options,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn freeze_order(
        &self,
        account_index: U31,
        order_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        WalletRpcClient::freeze_order(
            &self.http_client,
            account_index.into(),
            order_id.into(),
            options,
        )
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

    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error> {
        WalletRpcClient::node_enable_networking(&self.http_client, enable)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        WalletRpcClient::connect_to_peer(&self.http_client, address.to_string())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn disconnect_peer(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        WalletRpcClient::disconnect_peer(&self.http_client, peer_id.as_u64())
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

    async fn undiscourage_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        WalletRpcClient::undiscourage_address(&self.http_client, address)
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
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::abandon_transaction(
            &self.http_client,
            account_index.into(),
            HexEncoded::new(transaction_id),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn list_pending_transactions(
        &self,
        account_index: U31,
    ) -> Result<Vec<Id<Transaction>>, Self::Error> {
        WalletRpcClient::list_pending_transactions(&self.http_client, account_index.into())
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn list_transactions_by_address(
        &self,
        account_index: U31,
        address: Option<String>,
        limit: usize,
    ) -> Result<Vec<TxInfo>, Self::Error> {
        WalletRpcClient::list_transactions_by_address(
            &self.http_client,
            account_index.into(),
            address.map(Into::into),
            limit,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn get_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error> {
        WalletRpcClient::get_transaction(&self.http_client, account_index.into(), transaction_id)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn get_raw_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        WalletRpcClient::get_raw_transaction(
            &self.http_client,
            account_index.into(),
            transaction_id,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
        .map(|obj| obj.to_string())
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: U31,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        WalletRpcClient::get_raw_signed_transaction(
            &self.http_client,
            account_index.into(),
            transaction_id,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
        .map(|obj| obj.to_string())
    }

    async fn sign_raw_transaction(
        &self,
        account_index: U31,
        raw_tx: String,
        config: ControllerConfig,
    ) -> Result<SignRawTransactionResult, Self::Error> {
        let options = TransactionOptions::from_controller_config(&config);
        ColdWalletRpcClient::sign_raw_transaction(
            &self.http_client,
            account_index.into(),
            raw_tx.parse()?,
            options,
        )
        .await
        .map(|result| {
            let bytes = hex::decode(result.hex).expect("valid hex");
            let tx = if result.is_complete {
                PartialOrSignedTx::Signed(
                    SignedTransaction::decode_all(&mut bytes.as_slice()).expect("valid singed tx"),
                )
            } else {
                PartialOrSignedTx::Partial(
                    PartiallySignedTransaction::decode_all(&mut bytes.as_slice())
                        .expect("valid partially signed tx"),
                )
            };

            SignRawTransactionResult {
                transaction: tx,
                current_signatures: result.current_signatures,
                previous_signatures: result.previous_signatures,
            }
        })
        .map_err(WalletRpcError::ResponseError)
    }

    async fn sign_challenge(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        ColdWalletRpcClient::sign_challenge(
            &self.http_client,
            account_index.into(),
            challenge,
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
        .map(|h| h.to_string())
    }

    async fn sign_challenge_hex(
        &self,
        account_index: U31,
        challenge: String,
        address: String,
    ) -> Result<String, Self::Error> {
        ColdWalletRpcClient::sign_challenge_hex(
            &self.http_client,
            account_index.into(),
            challenge.parse()?,
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
        .map(|h| h.to_string())
    }

    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        ColdWalletRpcClient::verify_challenge(
            &self.http_client,
            message,
            signed_challenge.parse()?,
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn verify_challenge_hex(
        &self,
        message: String,
        signed_challenge: String,
        address: String,
    ) -> Result<(), Self::Error> {
        ColdWalletRpcClient::verify_challenge_hex(
            &self.http_client,
            message.parse()?,
            signed_challenge.parse()?,
            address.into(),
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<String>>>,
        only_transaction: bool,
    ) -> Result<ComposedTransaction, Self::Error> {
        let inputs = inputs.into_iter().map(Into::into).collect();
        let htlc_secrets = htlc_secrets
            .map(|s| s.into_iter().map(|s| s.map(|s| s.parse()).transpose()).collect())
            .transpose()?;
        WalletRpcClient::compose_transaction(
            &self.http_client,
            inputs,
            outputs,
            htlc_secrets,
            only_transaction,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn node_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        WalletRpcClient::node_best_block_id(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        WalletRpcClient::node_best_block_height(&self.http_client)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        WalletRpcClient::node_block_id(&self.http_client, block_height)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_generate_block(
        &self,
        account_index: U31,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::node_generate_block(&self.http_client, account_index.into(), transactions)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_generate_blocks(
        &self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), Self::Error> {
        WalletRpcClient::node_generate_blocks(&self.http_client, account_index.into(), block_count)
            .await
            .map_err(WalletRpcError::ResponseError)
    }

    async fn node_find_timestamps_for_staking(
        &self,
        pool_id: String,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, Self::Error> {
        WalletRpcClient::node_find_timestamps_for_staking(
            &self.http_client,
            pool_id.into(),
            min_height,
            max_height,
            seconds_to_check_for_height,
            check_all_timestamps_between_blocks,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }

    async fn node_block(&self, block_id: String) -> Result<Option<String>, Self::Error> {
        WalletRpcClient::node_block(&self.http_client, block_id.parse::<HexEncoded<_>>()?.take())
            .await
            .map_err(WalletRpcError::ResponseError)
            .map(|r| r.map(|b| b.to_string()))
    }

    async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        WalletRpcClient::node_get_block_ids_as_checkpoints(
            &self.http_client,
            start_height,
            end_height,
            step,
        )
        .await
        .map_err(WalletRpcError::ResponseError)
    }
}
