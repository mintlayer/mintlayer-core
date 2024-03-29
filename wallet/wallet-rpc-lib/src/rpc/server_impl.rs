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

use std::{fmt::Debug, num::NonZeroUsize, str::FromStr, time::Duration};

use chainstate::ChainInfo;
use common::{
    address::dehexify::dehexify_all_addresses,
    chain::{
        tokens::{IsTokenUnfreezable, TokenId},
        Block, DelegationId, Destination, GenBlock, PoolId, SignedTransaction, Transaction,
        TxOutput, UtxoOutPoint,
    },
    primitives::{time::Time, BlockHeight, Id, Idable},
};
use crypto::key::PrivateKey;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId};
use serialization::{hex::HexEncode, json_encoded::JsonEncoded};
use utils_networking::IpOrSocketAddress;
use wallet::{
    account::{PartiallySignedTransaction, TxInfo},
    version::get_version,
};
use wallet_controller::{
    types::{BlockInfo, CreatedBlockInfo, InspectTransaction, SeedWithPassPhrase, WalletInfo},
    ConnectedPeer, ControllerConfig, NodeInterface, UtxoState, UtxoStates, UtxoType, UtxoTypes,
};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

use crate::{
    rpc::{ColdWalletRpcServer, WalletEventsRpcServer, WalletRpc, WalletRpcServer},
    types::{
        AccountArg, AddressInfo, AddressWithUsageInfo, Balances, ComposedTransaction,
        CreatedWallet, DelegationInfo, HexEncoded, JsonValue, LegacyVrfPublicKeyInfo,
        MaybeSignedTransaction, NewAccountInfo, NewDelegation, NewTransaction, NftMetadata,
        NodeVersion, PoolInfo, PublicKeyInfo, RpcAddress, RpcAmountIn, RpcHexString, RpcTokenId,
        RpcUtxoState, RpcUtxoType, StakePoolBalance, StakingStatus, StandaloneAddress,
        StandaloneAddressWithDetails, TokenMetadata, TransactionOptions, TxOptionsOverrides,
        UtxoInfo, VrfPublicKeyInfo,
    },
    RpcError,
};

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletEventsRpcServer
    for WalletRpc<N>
{
    async fn subscribe_wallet_events(
        &self,
        pending: rpc::subscription::Pending,
    ) -> rpc::subscription::Reply {
        let wallet_events = self.wallet.subscribe().await?;
        rpc::subscription::connect_broadcast(wallet_events, pending).await
    }
}

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> ColdWalletRpcServer
    for WalletRpc<N>
{
    async fn shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.shutdown())
    }

    async fn version(&self) -> rpc::RpcResult<String> {
        Ok(get_version())
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    ) -> rpc::RpcResult<CreatedWallet> {
        let whether_to_store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };
        rpc::handle_result(
            self.create_wallet(
                path.into(),
                whether_to_store_seed_phrase,
                mnemonic,
                passphrase,
            )
            .await
            .map(|res| match res {
                crate::CreatedWallet::UserProvidedMnemonic => CreatedWallet::UserProvidedMnemonic,
                crate::CreatedWallet::NewlyGeneratedMnemonic(mnemonic, passphrase) => {
                    CreatedWallet::NewlyGeneratedMnemonic(mnemonic.to_string(), passphrase)
                }
            }),
        )
    }

    async fn open_wallet(
        &self,
        path: String,
        password: Option<String>,
        force_migrate_wallet_type: Option<bool>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.open_wallet(
                path.into(),
                password,
                force_migrate_wallet_type.unwrap_or(false),
            )
            .await,
        )
    }

    async fn close_wallet(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.close_wallet().await)
    }

    async fn wallet_info(&self) -> rpc::RpcResult<WalletInfo> {
        rpc::handle_result(self.wallet_info().await)
    }

    async fn get_seed_phrase(&self) -> rpc::RpcResult<Option<SeedWithPassPhrase>> {
        rpc::handle_result(self.get_seed_phrase().await)
    }

    async fn purge_seed_phrase(&self) -> rpc::RpcResult<Option<SeedWithPassPhrase>> {
        rpc::handle_result(self.purge_seed_phrase().await)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(self.set_lookahead_size(lookahead_size, i_know_what_i_am_doing).await)
    }

    async fn encrypt_private_keys(&self, password: String) -> rpc::RpcResult<()> {
        rpc::handle_result(self.encrypt_private_keys(password).await)
    }

    async fn remove_private_key_encryption(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.remove_private_key_encryption().await)
    }

    async fn unlock_private_keys(&self, password: String) -> rpc::RpcResult<()> {
        rpc::handle_result(self.unlock_private_keys(password).await)
    }

    async fn lock_private_key_encryption(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.lock_private_keys().await)
    }

    async fn issue_address(&self, account_arg: AccountArg) -> rpc::RpcResult<AddressInfo> {
        rpc::handle_result(self.issue_address(account_arg.index::<N>()?).await)
    }

    async fn reveal_public_key(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<PublicKeyInfo> {
        rpc::handle_result(self.find_public_key(account_arg.index::<N>()?, address).await)
    }

    async fn get_standalone_addresses(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<StandaloneAddress>> {
        rpc::handle_result(self.get_standalone_addresses(account_arg.index::<N>()?).await)
    }

    async fn get_standalone_address_details(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<StandaloneAddressWithDetails> {
        rpc::handle_result(
            self.get_standalone_address_details(account_arg.index::<N>()?, address).await,
        )
    }

    async fn get_issued_addresses(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>> {
        rpc::handle_result(self.get_issued_addresses(account_arg.index::<N>()?).await)
    }

    async fn new_vrf_public_key(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<VrfPublicKeyInfo> {
        rpc::handle_result(self.issue_vrf_key(account_arg.index::<N>()?).await)
    }

    async fn get_vrf_public_key(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<VrfPublicKeyInfo>> {
        rpc::handle_result(self.get_vrf_key_usage(account_arg.index::<N>()?).await)
    }

    async fn get_legacy_vrf_public_key(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<LegacyVrfPublicKeyInfo> {
        rpc::handle_result(self.get_legacy_vrf_public_key(account_arg.index::<N>()?).await)
    }

    async fn sign_raw_transaction(
        &self,
        account_arg: AccountArg,
        raw_tx: RpcHexString,
        options: TransactionOptions,
    ) -> rpc::RpcResult<MaybeSignedTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.sign_raw_transaction(account_arg.index::<N>()?, raw_tx, config)
                .await
                .map(|tx| {
                    let is_complete = tx.is_fully_signed(&self.chain_config);
                    let hex = if is_complete {
                        let tx = tx.into_signed_tx(&self.chain_config).expect("already checked");
                        tx.hex_encode()
                    } else {
                        tx.hex_encode()
                    };

                    MaybeSignedTransaction { hex, is_complete }
                }),
        )
    }

    async fn sign_challenge(
        &self,
        account_arg: AccountArg,
        challenge: String,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<RpcHexString> {
        rpc::handle_result(
            self.sign_challenge(account_arg.index::<N>()?, challenge.into_bytes(), address)
                .await
                .map(|m| RpcHexString::from_bytes(m.into_raw())),
        )
    }

    async fn sign_challenge_hex(
        &self,
        account_arg: AccountArg,
        challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<RpcHexString> {
        rpc::handle_result(
            self.sign_challenge(account_arg.index::<N>()?, challenge.into_bytes(), address)
                .await
                .map(|m| RpcHexString::from_bytes(m.into_raw())),
        )
    }

    async fn verify_challenge(
        &self,
        message: String,
        signed_challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<()> {
        let signed_challenge = signed_challenge.into_bytes();
        rpc::handle_result(self.verify_challenge(message.into_bytes(), signed_challenge, address))
    }

    async fn verify_challenge_hex(
        &self,
        message: RpcHexString,
        signed_challenge: RpcHexString,
        address: RpcAddress<Destination>,
    ) -> rpc::RpcResult<()> {
        let signed_challenge = signed_challenge.into_bytes();
        rpc::handle_result(self.verify_challenge(message.into_bytes(), signed_challenge, address))
    }
}

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletRpcServer for WalletRpc<N> {
    async fn rescan(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.rescan().await)
    }

    async fn sync(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.sync().await)
    }

    async fn best_block(&self) -> rpc::RpcResult<BlockInfo> {
        rpc::handle_result(self.best_block().await)
    }

    async fn create_account(&self, name: Option<String>) -> rpc::RpcResult<NewAccountInfo> {
        rpc::handle_result(self.create_account(name).await)
    }

    async fn rename_account(
        &self,
        account_arg: AccountArg,
        name: Option<String>,
    ) -> rpc::RpcResult<NewAccountInfo> {
        rpc::handle_result(self.update_account_name(account_arg.index::<N>()?, name).await)
    }

    async fn standalone_address_label_rename(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        label: Option<String>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.standalone_address_label_rename(account_arg.index::<N>()?, address, label)
                .await,
        )
    }

    async fn add_standalone_address(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.add_standalone_watch_only_address(
                account_arg.index::<N>()?,
                address,
                label,
                no_rescan.unwrap_or(false),
            )
            .await,
        )
    }

    async fn add_standalone_private_key(
        &self,
        account_arg: AccountArg,
        private_key: HexEncoded<PrivateKey>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.add_standalone_private_key(
                account_arg.index::<N>()?,
                private_key.take(),
                label,
                no_rescan.unwrap_or(false),
            )
            .await,
        )
    }

    async fn add_standalone_multisig(
        &self,
        account_arg: AccountArg,
        min_required_signatures: u8,
        public_keys: Vec<RpcAddress<Destination>>,
        label: Option<String>,
        no_rescan: Option<bool>,
    ) -> rpc::RpcResult<String> {
        rpc::handle_result(
            self.add_standalone_multisig(
                account_arg.index::<N>()?,
                min_required_signatures,
                public_keys,
                label,
                no_rescan.unwrap_or(false),
            )
            .await,
        )
    }

    async fn get_balance(
        &self,
        account_arg: AccountArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances> {
        rpc::handle_result(
            self.get_balance(
                account_arg.index::<N>()?,
                UtxoStates::ALL,
                with_locked.unwrap_or(WithLocked::Unlocked),
            )
            .await,
        )
    }

    async fn get_multisig_utxos(
        &self,
        account_arg: AccountArg,
        utxo_types: Vec<RpcUtxoType>,
        utxo_states: Vec<RpcUtxoState>,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Vec<JsonValue>> {
        let utxo_types = if utxo_types.is_empty() {
            UtxoTypes::ALL
        } else {
            utxo_types.iter().map(UtxoType::from).fold(UtxoTypes::NONE, |x, y| x | y)
        };

        let utxo_states = if utxo_states.is_empty() {
            UtxoState::Confirmed.into()
        } else {
            utxo_states.iter().map(UtxoState::from).fold(UtxoStates::NONE, |x, y| x | y)
        };

        let utxos = self
            .get_multisig_utxos(
                account_arg.index::<N>()?,
                utxo_types,
                utxo_states,
                with_locked.unwrap_or(WithLocked::Unlocked),
            )
            .await?;

        let result = utxos
            .into_iter()
            .map(|(utxo_outpoint, tx_ouput)| {
                let result = UtxoInfo::new(utxo_outpoint, tx_ouput, &self.chain_config)
                    .map(serde_json::to_value);
                rpc::handle_result(result)
            })
            .collect::<Result<Vec<_>, _>>();

        rpc::handle_result(result)
    }

    async fn get_utxos(&self, account_arg: AccountArg) -> rpc::RpcResult<Vec<JsonValue>> {
        let utxos = self
            .get_utxos(
                account_arg.index::<N>()?,
                UtxoTypes::ALL,
                UtxoStates::ALL,
                WithLocked::Unlocked,
            )
            .await?;

        let result = utxos
            .into_iter()
            .map(|(utxo_outpoint, tx_ouput)| {
                let result = UtxoInfo::new(utxo_outpoint, tx_ouput, &self.chain_config)
                    .map(serde_json::to_value);
                rpc::handle_result(result)
            })
            .collect::<Result<Vec<_>, _>>();

        rpc::handle_result(result)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<NewTransaction> {
        rpc::handle_result(self.submit_raw_transaction(tx, do_not_store, options).await)
    }

    async fn send_coins(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxos: Vec<UtxoOutPoint>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.send_coins(
                account_arg.index::<N>()?,
                address,
                amount,
                selected_utxos,
                config,
            )
            .await,
        )
    }

    async fn sweep_addresses(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        from_addresses: Vec<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.sweep_addresses(
                account.index::<N>()?,
                destination_address,
                from_addresses,
                config,
            )
            .await,
        )
    }

    async fn sweep_delegation(
        &self,
        account: AccountArg,
        destination_address: RpcAddress<Destination>,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.sweep_delegation(
                account.index::<N>()?,
                destination_address,
                delegation_id,
                config,
            )
            .await,
        )
    }

    async fn transaction_from_cold_input(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        selected_utxo: UtxoOutPoint,
        change_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<ComposedTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.request_send_coins(
                account_arg.index::<N>()?,
                address,
                amount,
                selected_utxo,
                change_address,
                config,
            )
            .await
            .map(|(tx, fees)| ComposedTransaction {
                hex: HexEncoded::new(tx).to_string(),
                fees,
            }),
        )
    }

    async fn transaction_inspect(
        &self,
        transaction: RpcHexString,
    ) -> rpc::RpcResult<InspectTransaction> {
        rpc::handle_result(self.transaction_inspect(transaction).await)
    }

    async fn create_stake_pool(
        &self,
        account_arg: AccountArg,
        amount: RpcAmountIn,
        cost_per_block: RpcAmountIn,
        margin_ratio_per_thousand: String,
        decommission_address: RpcAddress<Destination>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.create_stake_pool(
                account_arg.index::<N>()?,
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
                config,
            )
            .await,
        )
    }

    async fn decommission_stake_pool(
        &self,
        account_arg: AccountArg,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.decommission_stake_pool(
                account_arg.index::<N>()?,
                pool_id,
                output_address,
                config,
            )
            .await,
        )
    }

    async fn decommission_stake_pool_request(
        &self,
        account_arg: AccountArg,
        pool_id: RpcAddress<PoolId>,
        output_address: Option<RpcAddress<Destination>>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<HexEncoded<PartiallySignedTransaction>> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.decommission_stake_pool_request(
                account_arg.index::<N>()?,
                pool_id,
                output_address,
                config,
            )
            .await
            .map(HexEncoded::new),
        )
    }

    async fn create_delegation(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        pool_id: RpcAddress<PoolId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.create_delegation(account_arg.index::<N>()?, address, pool_id, config)
                .await,
        )
    }

    async fn delegate_staking(
        &self,
        account_arg: AccountArg,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.delegate_staking(account_arg.index::<N>()?, amount, delegation_id, config)
                .await,
        )
    }

    async fn withdraw_from_delegation(
        &self,
        account_arg: AccountArg,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        delegation_id: RpcAddress<DelegationId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };
        rpc::handle_result(
            self.withdraw_from_delegation(
                account_arg.index::<N>()?,
                address,
                amount,
                delegation_id,
                config,
            )
            .await,
        )
    }

    async fn start_staking(&self, account_arg: AccountArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.start_staking(account_arg.index::<N>()?).await)
    }

    async fn stop_staking(&self, account_arg: AccountArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.stop_staking(account_arg.index::<N>()?).await)
    }

    async fn staking_status(&self, account_arg: AccountArg) -> rpc::RpcResult<StakingStatus> {
        rpc::handle_result(self.staking_status(account_arg.index::<N>()?).await)
    }

    async fn list_pools(&self, account_arg: AccountArg) -> rpc::RpcResult<Vec<PoolInfo>> {
        rpc::handle_result(self.list_staking_pools(account_arg.index::<N>()?).await)
    }

    async fn list_pools_for_decommission(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<PoolInfo>> {
        rpc::handle_result(self.list_pools_for_decommission(account_arg.index::<N>()?).await)
    }

    async fn list_delegation_ids(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>> {
        rpc::handle_result(self.list_delegation_ids(account_arg.index::<N>()?).await)
    }

    async fn list_created_blocks_ids(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<CreatedBlockInfo>> {
        rpc::handle_result(self.list_created_blocks_ids(account_arg.index::<N>()?).await)
    }

    async fn issue_new_nft(
        &self,
        account_arg: AccountArg,
        destination_address: RpcAddress<Destination>,
        metadata: NftMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.issue_new_nft(
                account_arg.index::<N>()?,
                destination_address,
                metadata.into_metadata(),
                config,
            )
            .await,
        )
    }

    async fn issue_new_token(
        &self,
        account_arg: AccountArg,
        destination_address: RpcAddress<Destination>,
        metadata: TokenMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        let token_supply = metadata.token_supply::<N>()?;
        let is_freezable = metadata.is_freezable();
        rpc::handle_result(
            self.issue_new_token(
                account_arg.index::<N>()?,
                metadata.number_of_decimals,
                destination_address,
                metadata.token_ticker.into_bytes(),
                metadata.metadata_uri.into_bytes(),
                token_supply,
                is_freezable,
                config,
            )
            .await,
        )
    }

    async fn change_token_authority(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.change_token_authority(account_arg.index::<N>()?, token_id, address, config)
                .await,
        )
    }

    async fn mint_tokens(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.mint_tokens(account_arg.index::<N>()?, token_id, address, amount, config)
                .await,
        )
    }

    async fn unmint_tokens(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.unmint_tokens(account_arg.index::<N>()?, token_id, amount, config).await,
        )
    }

    async fn lock_token_supply(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.lock_token_supply(account_arg.index::<N>()?, token_id, config).await,
        )
    }

    async fn freeze_token(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        is_unfreezable: bool,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        let is_unfreezable = if is_unfreezable {
            IsTokenUnfreezable::Yes
        } else {
            IsTokenUnfreezable::No
        };

        rpc::handle_result(
            self.freeze_token(account_arg.index::<N>()?, token_id, is_unfreezable, config)
                .await,
        )
    }

    async fn unfreeze_token(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(self.unfreeze_token(account_arg.index::<N>()?, token_id, config).await)
    }

    async fn send_tokens(
        &self,
        account_arg: AccountArg,
        token_id: RpcAddress<TokenId>,
        address: RpcAddress<Destination>,
        amount: RpcAmountIn,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.send_tokens(account_arg.index::<N>()?, token_id, address, amount, config)
                .await,
        )
    }

    async fn deposit_data(
        &self,
        account_arg: AccountArg,
        data: RpcHexString,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb(),
            broadcast_to_mempool: true,
        };

        rpc::handle_result(
            self.deposit_data(account_arg.index::<N>()?, data.into_bytes(), config).await,
        )
    }

    async fn stake_pool_balance(
        &self,
        pool_id: RpcAddress<PoolId>,
    ) -> rpc::RpcResult<StakePoolBalance> {
        rpc::handle_result(
            self.stake_pool_balance(pool_id)
                .await
                .map(|balance| StakePoolBalance { balance }),
        )
    }

    async fn node_version(&self) -> rpc::RpcResult<NodeVersion> {
        rpc::handle_result(self.node_version().await.map(|version| NodeVersion { version }))
    }

    async fn node_shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.node_shutdown().await)
    }

    async fn node_enable_networking(&self, enable: bool) -> rpc::RpcResult<()> {
        rpc::handle_result(self.node_enable_networking(enable).await)
    }

    async fn connect_to_peer(&self, address: String) -> rpc::RpcResult<()> {
        let address =
            IpOrSocketAddress::from_str(&address).map_err(|_| RpcError::<N>::InvalidIpAddress)?;
        rpc::handle_result(self.connect_to_peer(address).await)
    }

    async fn disconnect_peer(&self, peer_id: u64) -> rpc::RpcResult<()> {
        rpc::handle_result(self.disconnect_peer(PeerId::from_u64(peer_id)).await)
    }

    async fn list_banned(&self) -> rpc::RpcResult<Vec<(BannableAddress, Time)>> {
        rpc::handle_result(self.list_banned().await)
    }

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: Duration,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(self.ban_address(address, duration).await)
    }

    async fn unban_address(&self, address: BannableAddress) -> rpc::RpcResult<()> {
        rpc::handle_result(self.unban_address(address).await)
    }

    async fn list_discouraged(&self) -> rpc::RpcResult<Vec<(BannableAddress, Time)>> {
        rpc::handle_result(self.list_discouraged().await)
    }

    async fn peer_count(&self) -> rpc::RpcResult<usize> {
        rpc::handle_result(self.peer_count().await)
    }

    async fn connected_peers(&self) -> rpc::RpcResult<Vec<ConnectedPeer>> {
        rpc::handle_result(self.connected_peers().await)
    }

    async fn reserved_peers(&self) -> rpc::RpcResult<Vec<SocketAddress>> {
        rpc::handle_result(self.reserved_peers().await)
    }

    async fn add_reserved_peer(&self, address: String) -> rpc::RpcResult<()> {
        let address =
            IpOrSocketAddress::from_str(&address).map_err(|_| RpcError::<N>::InvalidIpAddress)?;
        rpc::handle_result(self.add_reserved_peer(address).await)
    }

    async fn remove_reserved_peer(&self, address: String) -> rpc::RpcResult<()> {
        let address =
            IpOrSocketAddress::from_str(&address).map_err(|_| RpcError::<N>::InvalidIpAddress)?;
        rpc::handle_result(self.remove_reserved_peer(address).await)
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> rpc::RpcResult<()> {
        rpc::handle_result(self.submit_block(block).await)
    }

    async fn chainstate_info(&self) -> rpc::RpcResult<ChainInfo> {
        rpc::handle_result(self.chainstate_info().await)
    }

    async fn abandon_transaction(
        &self,
        account_arg: AccountArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.abandon_transaction(account_arg.index::<N>()?, transaction_id.take()).await,
        )
    }

    async fn list_pending_transactions(
        &self,
        account_arg: AccountArg,
    ) -> rpc::RpcResult<Vec<Id<Transaction>>> {
        rpc::handle_result(
            self.pending_transactions(account_arg.index::<N>()?)
                .await
                .map(|txs| txs.into_iter().map(|tx| tx.get_id()).collect::<Vec<_>>()),
        )
    }

    async fn list_transactions_by_address(
        &self,
        account_arg: AccountArg,
        address: Option<RpcAddress<Destination>>,
        limit: usize,
    ) -> rpc::RpcResult<Vec<TxInfo>> {
        rpc::handle_result(
            self.mainchain_transactions(account_arg.index::<N>()?, address, limit).await,
        )
    }

    async fn get_transaction(
        &self,
        account_arg: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<serde_json::Value> {
        rpc::handle_result(
            self.get_transaction(account_arg.index::<N>()?, transaction_id).await.map(|tx| {
                let str = JsonEncoded::new((tx.get_transaction(), tx.state())).to_string();
                let str = dehexify_all_addresses(&self.chain_config, &str);
                serde_json::from_str::<serde_json::Value>(&str)
            }),
        )
    }

    async fn get_raw_transaction(
        &self,
        account_arg: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<HexEncoded<Transaction>> {
        rpc::handle_result(
            self.get_transaction(account_arg.index::<N>()?, transaction_id)
                .await
                .map(|tx| HexEncoded::new(tx.into_transaction())),
        )
    }

    async fn get_raw_signed_transaction(
        &self,
        account_arg: AccountArg,
        transaction_id: Id<Transaction>,
    ) -> rpc::RpcResult<HexEncoded<SignedTransaction>> {
        rpc::handle_result(
            self.get_transaction(account_arg.index::<N>()?, transaction_id)
                .await
                .map(|tx| HexEncoded::new(tx.into_signed_transaction())),
        )
    }

    async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        only_transaction: bool,
    ) -> rpc::RpcResult<ComposedTransaction> {
        rpc::handle_result(
            self.compose_transaction(inputs, outputs, only_transaction)
                .await
                .map(|(tx, fees)| ComposedTransaction {
                    hex: tx.to_hex(),
                    fees,
                }),
        )
    }

    async fn node_best_block_id(&self) -> rpc::RpcResult<Id<GenBlock>> {
        rpc::handle_result(self.node_best_block_id().await)
    }

    async fn node_best_block_height(&self) -> rpc::RpcResult<BlockHeight> {
        rpc::handle_result(self.node_best_block_height().await)
    }

    async fn node_block_id(
        &self,
        block_height: BlockHeight,
    ) -> rpc::RpcResult<Option<Id<GenBlock>>> {
        rpc::handle_result(self.node_block_id(block_height).await)
    }

    async fn node_generate_block(
        &self,
        account_arg: AccountArg,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> rpc::RpcResult<()> {
        let transactions = transactions.into_iter().map(HexEncoded::take).collect();
        rpc::handle_result(
            self.generate_block(account_arg.index::<N>()?, transactions).await.map(|_| {}),
        )
    }

    async fn node_generate_blocks(
        &self,
        account_arg: AccountArg,
        block_count: u32,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.generate_blocks(account_arg.index::<N>()?, block_count).await.map(|_| {}),
        )
    }

    async fn node_block(&self, block_id: Id<Block>) -> rpc::RpcResult<Option<HexEncoded<Block>>> {
        rpc::handle_result(
            self.get_node_block(block_id)
                .await
                .map(|block_opt| block_opt.map(HexEncoded::new)),
        )
    }

    async fn node_get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> rpc::RpcResult<Vec<(BlockHeight, Id<GenBlock>)>> {
        rpc::handle_result(
            self.node_get_block_ids_as_checkpoints(start_height, end_height, step).await,
        )
    }
}
