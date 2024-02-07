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

use std::fmt::Debug;

use chainstate::ChainInfo;
use common::{
    address::dehexify::{dehexify_all_addresses, to_dehexified_json},
    chain::{tokens::IsTokenUnfreezable, Block, SignedTransaction, Transaction, UtxoOutPoint},
    primitives::{DecimalAmount, Id, Idable},
};
use node_comm::node_traits::NodeInterface;
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress,
    socket_address::SocketAddress, PeerId,
};
use serialization::{hex::HexEncode, hex_encoded::HexEncoded, json_encoded::JsonEncoded};
use wallet_controller::{ConnectedPeer, ControllerConfig};
use wallet_rpc_lib::{
    types::{
        AccountIndexArg, AddressInfo, AddressWithUsageInfo, Balances, BlockInfo, DelegationInfo,
        NewAccountInfo, NewDelegation, NewTransaction, NftMetadata, NodeVersion, PoolInfo,
        PublicKeyInfo, RpcTokenId, SeedPhrase, StakePoolBalance, StakingStatus, TokenMetadata,
        TxOptionsOverrides, UtxoInfo, VrfPublicKeyInfo,
    },
    WalletRpc,
};
use wallet_types::{
    seed_phrase::StoreSeedPhrase,
    utxo_types::{UtxoStates, UtxoTypes},
    with_locked::WithLocked,
};

use crate::wallet_rpc_traits::ColdWalletInterface;

pub struct WalletRpcHandlesClient<N: Clone> {
    wallet_rpc: WalletRpc<N>,
    server_rpc: Option<rpc::Rpc>,
}

// impl<N> std::fmt::Debug for WalletRpcHandlesClient<N> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("WalletRpcHandlesClient").finish()
//     }
// }

#[derive(thiserror::Error, Debug)]
pub enum WalletRpcHandlesClientError<N: NodeInterface> {
    #[error("{0}")]
    WalletRpcError(#[from] wallet_rpc_lib::RpcError<N>),

    #[error("{0}")]
    SerializationError(#[from] serde_json::Error),
}

impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> WalletRpcHandlesClient<N> {
    pub async fn new(
        wallet_rpc: WalletRpc<N>,
        server_rpc: Option<rpc::Rpc>,
    ) -> Result<Self, WalletRpcHandlesClientError<N>> {
        let mut result = Self {
            wallet_rpc,
            server_rpc,
        };
        result.basic_start_test().await?;
        Ok(result)
    }

    async fn basic_start_test(&mut self) -> Result<(), WalletRpcHandlesClientError<N>> {
        // Call an arbitrary function to make sure that connection is established
        //FIXME don't call shutdown
        self.shutdown().await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl<N: NodeInterface + Clone + Send + Sync + 'static + Debug> ColdWalletInterface
    for WalletRpcHandlesClient<N>
{
    type Error = WalletRpcHandlesClientError<N>;

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        if let Some(rpc) = self.server_rpc.take() {
            rpc.shutdown().await;
        }
        Ok(())
    }

    async fn create_wallet(
        &self,
        path: String,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
    ) -> Result<(), Self::Error> {
        let whether_to_store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };
        self.wallet_rpc
            .create_wallet(path.into(), whether_to_store_seed_phrase, mnemonic)
            .await?;
        Ok(())
    }

    async fn open_wallet(&self, path: String, password: Option<String>) -> Result<(), Self::Error> {
        self.wallet_rpc
            .open_wallet(path.into(), password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn close_wallet(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .close_wallet()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .sync()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn rescan(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .rescan()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_seed_phrase(&self) -> Result<SeedPhrase, Self::Error> {
        self.wallet_rpc
            .get_seed_phrase()
            .await
            .map(|seed_phrase| SeedPhrase { seed_phrase })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn purge_seed_phrase(&self) -> Result<SeedPhrase, Self::Error> {
        self.wallet_rpc
            .purge_seed_phrase()
            .await
            .map(|seed_phrase| SeedPhrase { seed_phrase })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn set_lookahead_size(
        &self,
        lookahead_size: u32,
        i_know_what_i_am_doing: bool,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .set_lookahead_size(lookahead_size, i_know_what_i_am_doing)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn encrypt_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .encrypt_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_private_key_encryption()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unlock_private_keys(&self, password: String) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unlock_private_keys(password)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_private_key_encryption(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .lock_private_keys()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn best_block(&self) -> Result<BlockInfo, Self::Error> {
        self.wallet_rpc
            .best_block()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_account(&self, name: Option<String>) -> Result<NewAccountInfo, Self::Error> {
        self.wallet_rpc
            .create_account(name)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_issued_addresses(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<AddressWithUsageInfo>, Self::Error> {
        self.wallet_rpc
            .get_issued_addresses(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_address(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<AddressInfo, Self::Error> {
        self.wallet_rpc
            .issue_address(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reveal_public_key(
        &self,
        account_index: AccountIndexArg,
        address: String,
    ) -> Result<PublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .find_public_key(account_index.index::<N>()?, address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_balance(
        &self,
        account_index: AccountIndexArg,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Balances, Self::Error> {
        self.wallet_rpc
            .get_balance(account_index.index::<N>()?, utxo_states, with_locked)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_utxos(
        &self,
        account_index: AccountIndexArg,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Result<Vec<serde_json::Value>, Self::Error> {
        let utxos = self
            .wallet_rpc
            .get_utxos(
                account_index.index::<N>()?,
                utxo_types,
                utxo_states,
                with_locked,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)?;

        utxos
            .into_iter()
            .map(|utxo| {
                to_dehexified_json(self.wallet_rpc.chain_config(), UtxoInfo::from_tuple(utxo))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(WalletRpcHandlesClientError::SerializationError)
    }

    async fn submit_raw_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        do_not_store: bool,
        options: TxOptionsOverrides,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .submit_raw_transaction(tx, do_not_store, options)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_coins(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        selected_utxos: Vec<UtxoOutPoint>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .send_coins(
                account_index.index::<N>()?,
                address,
                amount,
                selected_utxos,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
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
        self.wallet_rpc
            .create_stake_pool(
                account_index.index::<N>()?,
                amount,
                cost_per_block,
                margin_ratio_per_thousand,
                decommission_address,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn decommission_stake_pool(
        &self,
        account_index: AccountIndexArg,
        pool_id: String,
        output_address: Option<String>,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .decommission_stake_pool(account_index.index::<N>()?, pool_id, output_address, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn create_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        pool_id: String,
        config: ControllerConfig,
    ) -> Result<NewDelegation, Self::Error> {
        self.wallet_rpc
            .create_delegation(account_index.index::<N>()?, address, pool_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn delegate_staking(
        &self,
        account_index: AccountIndexArg,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .delegate_staking(account_index.index::<N>()?, amount, delegation_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn withdraw_from_delegation(
        &self,
        account_index: AccountIndexArg,
        address: String,
        amount: DecimalAmount,
        delegation_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .withdraw_from_delegation(
                account_index.index::<N>()?,
                address,
                amount,
                delegation_id,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn start_staking(&self, account_index: AccountIndexArg) -> Result<(), Self::Error> {
        self.wallet_rpc
            .start_staking(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stop_staking(&self, account_index: AccountIndexArg) -> Result<(), Self::Error> {
        self.wallet_rpc
            .stop_staking(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn staking_status(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<StakingStatus, Self::Error> {
        self.wallet_rpc
            .staking_status(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pool_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<PoolInfo>, Self::Error> {
        self.wallet_rpc
            .list_pool_ids(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn stake_pool_balance(&self, pool_id: String) -> Result<StakePoolBalance, Self::Error> {
        self.wallet_rpc
            .stake_pool_balance(pool_id)
            .await
            .map(|balance| StakePoolBalance { balance })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_delegation_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<DelegationInfo>, Self::Error> {
        self.wallet_rpc
            .list_delegation_ids(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_created_blocks_ids(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<BlockInfo>, Self::Error> {
        self.wallet_rpc
            .list_created_blocks_ids(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn new_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<VrfPublicKeyInfo, Self::Error> {
        self.wallet_rpc
            .issue_vrf_key(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_vrf_public_key(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<VrfPublicKeyInfo>, Self::Error> {
        self.wallet_rpc
            .get_vrf_key_usage(account_index.index::<N>()?)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_nft(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: NftMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        self.wallet_rpc
            .issue_new_nft(
                account_index.index::<N>()?,
                destination_address,
                metadata.into_metadata(),
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn issue_new_token(
        &self,
        account_index: AccountIndexArg,
        destination_address: String,
        metadata: TokenMetadata,
        config: ControllerConfig,
    ) -> Result<RpcTokenId, Self::Error> {
        let token_supply = metadata.token_supply::<N>(self.wallet_rpc.chain_config())?;
        let is_freezable = metadata.is_freezable();
        self.wallet_rpc
            .issue_new_token(
                account_index.index::<N>()?,
                metadata.number_of_decimals,
                destination_address,
                metadata.token_ticker.into_bytes(),
                metadata.metadata_uri.into_bytes(),
                token_supply,
                is_freezable,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn change_token_authority(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .change_token_authority(account_index.index::<N>()?, token_id, address, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn mint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .mint_tokens(
                account_index.index::<N>()?,
                token_id,
                address,
                amount,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unmint_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .unmint_tokens(account_index.index::<N>()?, token_id, amount, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn lock_token_supply(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .lock_token_supply(account_index.index::<N>()?, token_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn freeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        is_unfreezable: bool,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        let is_unfreezable = if is_unfreezable {
            IsTokenUnfreezable::Yes
        } else {
            IsTokenUnfreezable::No
        };
        self.wallet_rpc
            .freeze_token(
                account_index.index::<N>()?,
                token_id,
                is_unfreezable,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unfreeze_token(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .unfreeze_token(account_index.index::<N>()?, token_id, config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn send_tokens(
        &self,
        account_index: AccountIndexArg,
        token_id: String,
        address: String,
        amount: DecimalAmount,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .send_tokens(
                account_index.index::<N>()?,
                token_id,
                address,
                amount,
                config,
            )
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn deposit_data(
        &self,
        account_index: AccountIndexArg,
        data: String,
        config: ControllerConfig,
    ) -> Result<NewTransaction, Self::Error> {
        self.wallet_rpc
            .deposit_data(account_index.index::<N>()?, data.into_bytes(), config)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_version(&self) -> Result<NodeVersion, Self::Error> {
        self.wallet_rpc
            .node_version()
            .await
            .map(|version| NodeVersion { version })
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        self.wallet_rpc
            .node_shutdown()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connect_to_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .connect_to_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn disconnect_peer(&self, peer_id: u64) -> Result<(), Self::Error> {
        self.wallet_rpc
            .disconnect_peer(PeerId::from_u64(peer_id))
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_banned(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_banned()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn ban_address(
        &self,
        address: BannableAddress,
        duration: std::time::Duration,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .ban_address(address, duration)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn unban_address(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .unban_address(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_discouraged(
        &self,
    ) -> Result<Vec<(BannableAddress, common::primitives::time::Time)>, Self::Error> {
        self.wallet_rpc
            .list_discouraged()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn peer_count(&self) -> Result<usize, Self::Error> {
        self.wallet_rpc
            .peer_count()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        self.wallet_rpc
            .connected_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn reserved_peers(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        self.wallet_rpc
            .reserved_peers()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn add_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .add_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn remove_reserved_peer(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.wallet_rpc
            .remove_reserved_peer(address)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> Result<(), Self::Error> {
        self.wallet_rpc
            .submit_block(block)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        self.wallet_rpc
            .chainstate_info()
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn abandon_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<(), Self::Error> {
        self.wallet_rpc
            .abandon_transaction(account_index.index::<N>()?, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn list_pending_transactions(
        &self,
        account_index: AccountIndexArg,
    ) -> Result<Vec<Id<Transaction>>, Self::Error> {
        self.wallet_rpc
            .pending_transactions(account_index.index::<N>()?)
            .await
            .map(|txs| txs.into_iter().map(|tx| tx.get_id()).collect::<Vec<_>>())
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<serde_json::Value, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index.index::<N>()?, transaction_id)
            .await
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
            .and_then(|tx| {
                let str = JsonEncoded::new(tx.get_transaction()).to_string();
                let str = dehexify_all_addresses(self.wallet_rpc.chain_config(), &str);
                serde_json::from_str::<serde_json::Value>(&str)
                    .map_err(WalletRpcHandlesClientError::SerializationError)
            })
    }

    async fn get_raw_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index.index::<N>()?, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }

    async fn get_raw_signed_transaction(
        &self,
        account_index: AccountIndexArg,
        transaction_id: Id<Transaction>,
    ) -> Result<String, Self::Error> {
        self.wallet_rpc
            .get_transaction(account_index.index::<N>()?, transaction_id)
            .await
            .map(|tx| HexEncode::hex_encode(tx.get_signed_transaction()))
            .map_err(WalletRpcHandlesClientError::WalletRpcError)
    }
}
