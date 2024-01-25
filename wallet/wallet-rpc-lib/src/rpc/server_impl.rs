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

use chainstate::ChainInfo;
use common::{
    address::dehexify::{dehexify_all_addresses, to_dehexified_json},
    chain::{tokens::IsTokenUnfreezable, Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id, Idable, H256},
};
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress, PeerId,
};
use serialization::{hex::HexEncode, json_encoded::JsonEncoded};
use std::{fmt::Debug, str::FromStr};
use wallet_controller::{
    types::BlockInfo, ConnectedPeer, ControllerConfig, NodeInterface, UtxoStates, UtxoTypes,
};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

use crate::{
    rpc::{WalletRpc, WalletRpcServer},
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, DecimalAmount,
        DelegationInfo, EmptyArgs, HexEncoded, JsonValue, NewAccountInfo, NewDelegation,
        NewTransaction, NftMetadata, NodeVersion, PoolInfo, PublicKeyInfo, RpcTokenId, SeedPhrase,
        StakePoolBalance, TokenMetadata, TransactionOptions, TxOptionsOverrides, UtxoInfo,
        VrfPublicKeyInfo,
    },
    RpcError,
};

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletRpcServer for WalletRpc<N> {
    async fn shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.shutdown())
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> rpc::RpcResult<()> {
        let whether_to_store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };
        rpc::handle_result(
            self.create_wallet(path.into(), whether_to_store_seed_phrase, mnemonic)
                .await
                .map(|_| ()),
        )
    }

    async fn open_wallet(&self, path: String, password: Option<String>) -> rpc::RpcResult<()> {
        rpc::handle_result(self.open_wallet(path.into(), password).await)
    }

    async fn close_wallet(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.close_wallet().await)
    }

    async fn rescan(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.rescan().await)
    }

    async fn sync(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.sync().await)
    }

    async fn get_seed_phrase(&self) -> rpc::RpcResult<SeedPhrase> {
        rpc::handle_result(
            self.get_seed_phrase().await.map(|seed_phrase| SeedPhrase { seed_phrase }),
        )
    }

    async fn purge_seed_phrase(&self) -> rpc::RpcResult<SeedPhrase> {
        rpc::handle_result(
            self.purge_seed_phrase().await.map(|seed_phrase| SeedPhrase { seed_phrase }),
        )
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

    async fn best_block(&self, empty_args: EmptyArgs) -> rpc::RpcResult<BlockInfo> {
        rpc::handle_result(self.best_block(empty_args).await)
    }

    async fn create_account(
        &self,
        name: Option<String>,
        _empty_args: EmptyArgs,
    ) -> rpc::RpcResult<NewAccountInfo> {
        rpc::handle_result(self.create_account(name).await)
    }

    async fn issue_address(&self, account_index: AccountIndexArg) -> rpc::RpcResult<AddressInfo> {
        rpc::handle_result(self.issue_address(account_index.index::<N>()?).await)
    }

    async fn issue_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<PublicKeyInfo> {
        rpc::handle_result(self.issue_public_key(account_index.index::<N>()?).await)
    }

    async fn get_issued_addresses(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<AddressWithUsageInfo>> {
        rpc::handle_result(self.get_issued_addresses(account_index.index::<N>()?).await)
    }

    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        with_locked: Option<WithLocked>,
    ) -> rpc::RpcResult<Balances> {
        rpc::handle_result(
            self.get_balance(
                account_index.index::<N>()?,
                UtxoStates::ALL,
                with_locked.unwrap_or(WithLocked::Unlocked),
            )
            .await,
        )
    }

    async fn get_utxos(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<JsonValue>> {
        let utxos = self
            .get_utxos(
                account_index.index::<N>()?,
                UtxoTypes::ALL,
                UtxoStates::ALL,
                WithLocked::Unlocked,
            )
            .await?;

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
        rpc::handle_result(self.submit_raw_transaction(tx, options).await)
    }

    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount_str: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.send_coins(
                account_index.index::<N>()?,
                address,
                amount_str,
                vec![],
                config,
            )
            .await,
        )
    }

    async fn create_stake_pool(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        cost_per_block: DecimalAmount,
        margin_ratio_per_thousand: String,
        decommission_address: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.create_stake_pool(
                account_index.index::<N>()?,
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
        account_index: AccountIndexArg,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.decommission_stake_pool(account_index.index::<N>()?, pool_id, config).await,
        )
    }

    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewDelegation> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.create_delegation(account_index.index::<N>()?, address, pool_id, config)
                .await,
        )
    }

    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.delegate_staking(account_index.index::<N>()?, amount, delegation_id, config)
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
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };
        rpc::handle_result(
            self.send_from_delegation_to_address(
                account_index.index::<N>()?,
                address,
                amount,
                delegation_id,
                config,
            )
            .await,
        )
    }

    async fn start_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.start_staking(account_index.index::<N>()?).await)
    }

    async fn stop_staking(&self, account_index: AccountIndexArg) -> rpc::RpcResult<()> {
        rpc::handle_result(self.stop_staking(account_index.index::<N>()?).await)
    }

    async fn list_pool_ids(&self, account_index: AccountIndexArg) -> rpc::RpcResult<Vec<PoolInfo>> {
        rpc::handle_result(self.list_pool_ids(account_index.index::<N>()?).await)
    }

    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<DelegationInfo>> {
        rpc::handle_result(self.list_delegation_ids(account_index.index::<N>()?).await)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<BlockInfo>> {
        rpc::handle_result(self.list_created_blocks_ids(account_index.index::<N>()?).await)
    }

    async fn issue_new_nft(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: NftMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.issue_new_nft(
                account_index.index::<N>()?,
                destination_address,
                metadata.into_metadata(),
                config,
            )
            .await,
        )
    }

    async fn issue_new_token(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: TokenMetadata,
        options: TransactionOptions,
    ) -> rpc::RpcResult<RpcTokenId> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        let token_supply = metadata.token_supply::<N>(&self.chain_config)?;
        let is_freezable = metadata.is_freezable();
        rpc::handle_result(
            self.issue_new_token(
                account_index.index::<N>()?,
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
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.change_token_authority(account_index.index::<N>()?, token_id, address, config)
                .await,
        )
    }

    async fn mint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.mint_tokens(
                account_index.index::<N>()?,
                token_id,
                address,
                amount,
                config,
            )
            .await,
        )
    }

    async fn unmint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.unmint_tokens(account_index.index::<N>()?, token_id, amount, config).await,
        )
    }

    async fn lock_token_supply(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.lock_token_supply(account_index.index::<N>()?, token_id, config).await,
        )
    }

    async fn freeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        is_unfreezable: bool,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        let is_unfreezable = if is_unfreezable {
            IsTokenUnfreezable::Yes
        } else {
            IsTokenUnfreezable::No
        };

        rpc::handle_result(
            self.freeze_token(
                account_index.index::<N>()?,
                token_id,
                is_unfreezable,
                config,
            )
            .await,
        )
    }

    async fn unfreeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(self.unfreeze_token(account_index.index::<N>()?, token_id, config).await)
    }

    async fn send_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.send_tokens(
                account_index.index::<N>()?,
                token_id,
                address,
                amount,
                config,
            )
            .await,
        )
    }

    async fn deposit_data(
        &self,
        account_index: AccountIndexArg,
        data: String,
        options: TransactionOptions,
    ) -> rpc::RpcResult<NewTransaction> {
        let config = ControllerConfig {
            in_top_x_mb: options.in_top_x_mb,
        };

        rpc::handle_result(
            self.deposit_data(account_index.index::<N>()?, data.into_bytes(), config).await,
        )
    }

    async fn stake_pool_balance(&self, pool_id: String) -> rpc::RpcResult<StakePoolBalance> {
        rpc::handle_result(
            self.stake_pool_balance(pool_id)
                .await
                .map(|balance| StakePoolBalance { balance }),
        )
    }

    async fn get_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<VrfPublicKeyInfo>> {
        rpc::handle_result(self.get_vrf_key_usage(account_index.index::<N>()?).await)
    }

    async fn node_version(&self) -> rpc::RpcResult<NodeVersion> {
        rpc::handle_result(self.node_version().await.map(|version| NodeVersion { version }))
    }

    async fn node_shutdown(&self) -> rpc::RpcResult<()> {
        rpc::handle_result(self.node_shutdown().await)
    }

    async fn connect_to_peer(&self, address: String) -> rpc::RpcResult<()> {
        let address =
            IpOrSocketAddress::from_str(&address).map_err(|_| RpcError::<N>::InvalidIpAddress)?;
        rpc::handle_result(self.connect_to_peer(address).await)
    }

    async fn disconnect_peer(&self, peer_id: u64) -> rpc::RpcResult<()> {
        rpc::handle_result(self.disconnect_peer(PeerId::from_u64(peer_id)).await)
    }

    async fn list_banned(&self) -> rpc::RpcResult<Vec<BannableAddress>> {
        rpc::handle_result(self.list_banned().await)
    }

    async fn ban_address(&self, address: BannableAddress) -> rpc::RpcResult<()> {
        rpc::handle_result(self.ban_address(address).await)
    }

    async fn unban_address(&self, address: BannableAddress) -> rpc::RpcResult<()> {
        rpc::handle_result(self.unban_address(address).await)
    }

    async fn peer_count(&self) -> rpc::RpcResult<usize> {
        rpc::handle_result(self.peer_count().await)
    }

    async fn connected_peers(&self) -> rpc::RpcResult<Vec<ConnectedPeer>> {
        rpc::handle_result(self.connected_peers().await)
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

    async fn node_block(&self, block_id: String) -> rpc::RpcResult<Option<Block>> {
        let hash = H256::from_str(&block_id).map_err(|_| RpcError::<N>::InvalidBlockId)?;
        rpc::handle_result(self.get_node_block(hash.into()).await)
    }

    async fn node_generate_block(
        &self,
        account_index: AccountIndexArg,
        transactions: Vec<HexEncoded<SignedTransaction>>,
    ) -> rpc::RpcResult<()> {
        let transactions = transactions.into_iter().map(HexEncoded::take).collect();
        rpc::handle_result(
            self.generate_block(account_index.index::<N>()?, transactions).await.map(|_| {}),
        )
    }

    async fn node_generate_blocks(
        &self,
        account_index: AccountIndexArg,
        block_count: u32,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.generate_blocks(account_index.index::<N>()?, block_count).await.map(|_| {}),
        )
    }

    async fn abandon_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<()> {
        rpc::handle_result(
            self.abandon_transaction(account_index.index::<N>()?, transaction_id.take())
                .await,
        )
    }

    async fn list_pending_transactions(
        &self,
        account_index: AccountIndexArg,
    ) -> rpc::RpcResult<Vec<Id<Transaction>>> {
        rpc::handle_result(
            self.pending_transactions(account_index.index::<N>()?)
                .await
                .map(|txs| txs.into_iter().map(|tx| tx.get_id()).collect::<Vec<_>>()),
        )
    }

    async fn get_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<serde_json::Value> {
        rpc::handle_result(
            self.get_transaction(account_index.index::<N>()?, transaction_id.take())
                .await
                .map(|tx| {
                    let str = JsonEncoded::new(tx.get_transaction()).to_string();
                    let str = dehexify_all_addresses(&self.chain_config, &str);
                    serde_json::from_str::<serde_json::Value>(&str)
                }),
        )
    }

    async fn get_raw_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<String> {
        rpc::handle_result(
            self.get_transaction(account_index.index::<N>()?, transaction_id.take())
                .await
                .map(|tx| HexEncode::hex_encode(tx.get_transaction())),
        )
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: HexEncoded<Id<Transaction>>,
    ) -> rpc::RpcResult<String> {
        rpc::handle_result(
            self.get_transaction(account_index.index::<N>()?, transaction_id.take())
                .await
                .map(|tx| HexEncode::hex_encode(tx.get_signed_transaction())),
        )
    }

    async fn subscribe_wallet_events(
        &self,
        pending: rpc::subscription::Pending,
        _options: EmptyArgs,
    ) -> rpc::subscription::Reply {
        let wallet_events = self.wallet.subscribe().await?;
        rpc::subscription::connect_broadcast(wallet_events, pending).await
    }
}
