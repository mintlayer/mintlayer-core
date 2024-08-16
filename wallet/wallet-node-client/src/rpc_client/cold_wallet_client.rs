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

use std::{num::NonZeroUsize, time::Duration};

use blockprod::TimestampSearchData;
use chainstate::ChainInfo;
use common::{
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        Block, DelegationId, Destination, GenBlock, OrderId, PoolId, RpcOrderInfo,
        SignedTransaction, Transaction,
    },
    primitives::{time::Time, Amount, BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::EndToEndPublicKey;
use mempool::{tx_accumulator::PackingStrategy, tx_options::TxOptionsOverrides, FeeRate};
use p2p::{
    interface::types::ConnectedPeer,
    types::{bannable_address::BannableAddress, socket_address::SocketAddress, PeerId},
};
use utils_networking::IpOrSocketAddress;
use wallet_types::wallet_type::WalletControllerMode;

use crate::node_traits::NodeInterface;

use super::ColdWalletClient;

#[derive(thiserror::Error, Debug)]
pub enum ColdWalletRpcError {
    #[error("Method is not available in cold wallet mode")]
    NotAvailable,
}

#[async_trait::async_trait]
impl NodeInterface for ColdWalletClient {
    type Error = ColdWalletRpcError;

    fn is_cold_wallet_node(&self) -> WalletControllerMode {
        WalletControllerMode::Cold
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        let genesis = self.chain_config.genesis_block();
        Ok(ChainInfo {
            best_block_id: self.chain_config.genesis_block_id(),
            best_block_height: BlockHeight::zero(),
            best_block_timestamp: genesis.timestamp(),
            median_time: genesis.timestamp(),
            is_initial_block_download: false,
        })
    }

    async fn get_block(&self, _block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_mainchain_blocks(
        &self,
        _from: BlockHeight,
        _max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_block_ids_as_checkpoints(
        &self,
        _start_height: BlockHeight,
        _end_height: BlockHeight,
        _step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_best_block_height(&self) -> Result<common::primitives::BlockHeight, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_block_id_at_height(
        &self,
        _height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_last_common_ancestor(
        &self,
        _first_block: Id<GenBlock>,
        _second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_stake_pool_balance(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<Amount>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_staker_balance(&self, _pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_pool_decommission_destination(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<Destination>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_delegation_share(
        &self,
        _pool_id: PoolId,
        _delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_token_info(
        &self,
        _token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_order_info(
        &self,
        _order_id: OrderId,
    ) -> Result<Option<RpcOrderInfo>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn blockprod_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn generate_block_e2e(
        &self,
        _encrypted_input_data: Vec<u8>,
        _public_key: EndToEndPublicKey,
        _transactions: Vec<SignedTransaction>,
        _transaction_ids: Vec<Id<Transaction>>,
        _packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn collect_timestamp_search_data(
        &self,
        _pool_id: PoolId,
        _min_height: BlockHeight,
        _max_height: Option<BlockHeight>,
        _seconds_to_check_for_height: u64,
        _all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn generate_block(
        &self,
        _input_data: GenerateBlockInputData,
        _transactions: Vec<SignedTransaction>,
        _transaction_ids: Vec<Id<Transaction>>,
        _packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn submit_block(&self, _block: Block) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn submit_transaction(
        &self,
        _tx: SignedTransaction,
        _options: TxOptionsOverrides,
    ) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn node_enable_networking(&self, _enable: bool) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn node_version(&self) -> Result<String, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_connect(&self, _address: IpOrSocketAddress) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_disconnect(&self, _peer_id: PeerId) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_list_banned(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_ban(
        &self,
        _address: BannableAddress,
        _duration: Duration,
    ) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_unban(&self, _address: BannableAddress) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_list_discouraged(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_undiscourage(&self, _address: BannableAddress) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_get_reserved_nodes(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_add_reserved_node(&self, _address: IpOrSocketAddress) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn p2p_remove_reserved_node(
        &self,
        _address: IpOrSocketAddress,
    ) -> Result<(), Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn mempool_get_fee_rate(&self, _in_top_x_mb: usize) -> Result<FeeRate, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }

    async fn get_utxo(
        &self,
        _outpoint: common::chain::UtxoOutPoint,
    ) -> Result<Option<common::chain::TxOutput>, Self::Error> {
        Err(ColdWalletRpcError::NotAvailable)
    }
}
