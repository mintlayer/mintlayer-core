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

use chainstate::ChainInfo;
use common::{
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        Block, DelegationId, Destination, GenBlock, OrderId, PoolId, RpcOrderInfo,
        SignedTransaction, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{time::Time, Amount, BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::EndToEndPublicKey;
use mempool::{tx_accumulator::PackingStrategy, tx_options::TxOptionsOverrides, FeeRate};
use p2p::types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use utils_networking::IpOrSocketAddress;
use wallet_types::wallet_type::WalletControllerMode;

pub use p2p::{interface::types::ConnectedPeer, types::peer_id::PeerId};

#[mockall::automock(type Error = anyhow::Error;)]
#[async_trait::async_trait]
pub trait NodeInterface {
    // Note: not requiring the `Error` trait here so that `anyhow::Error` can be used.
    type Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static;

    async fn is_cold_wallet_node(&self) -> WalletControllerMode;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error>;
    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error>;
    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error>;
    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error>;
    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error>;
    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error>;
    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error>;
    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error>;
    async fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error>;
    async fn get_staker_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error>;
    async fn get_pool_decommission_destination(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<Destination>, Self::Error>;
    async fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error>;
    async fn get_token_info(&self, token_id: TokenId) -> Result<Option<RPCTokenInfo>, Self::Error>;
    async fn get_order_info(&self, order_id: OrderId) -> Result<Option<RpcOrderInfo>, Self::Error>;
    async fn blockprod_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error>;
    async fn generate_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error>;
    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        public_key: EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error>;
    async fn collect_timestamp_search_data(
        &self,
        pool_id: PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<blockprod::TimestampSearchData, Self::Error>;
    async fn submit_block(&self, block: Block) -> Result<(), Self::Error>;
    async fn submit_transaction(
        &self,
        tx: SignedTransaction,
        opts: TxOptionsOverrides,
    ) -> Result<(), Self::Error>;

    async fn node_shutdown(&self) -> Result<(), Self::Error>;
    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error>;
    async fn node_version(&self) -> Result<String, Self::Error>;

    async fn p2p_connect(&self, address: IpOrSocketAddress) -> Result<(), Self::Error>;
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error>;
    async fn p2p_list_banned(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error>;
    async fn p2p_ban(
        &self,
        address: BannableAddress,
        duration: Duration,
    ) -> Result<(), Self::Error>;
    async fn p2p_unban(&self, address: BannableAddress) -> Result<(), Self::Error>;
    async fn p2p_list_discouraged(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error>;
    async fn p2p_undiscourage(&self, address: BannableAddress) -> Result<(), Self::Error>;
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error>;
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error>;
    async fn p2p_get_reserved_nodes(&self) -> Result<Vec<SocketAddress>, Self::Error>;
    async fn p2p_add_reserved_node(&self, address: IpOrSocketAddress) -> Result<(), Self::Error>;
    async fn p2p_remove_reserved_node(&self, address: IpOrSocketAddress)
        -> Result<(), Self::Error>;

    async fn mempool_get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Self::Error>;
    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error>;

    async fn get_utxo(&self, outpoint: UtxoOutPoint) -> Result<Option<TxOutput>, Self::Error>;
}
