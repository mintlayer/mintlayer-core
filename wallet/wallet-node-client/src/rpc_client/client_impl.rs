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

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    time::Duration,
};

use futures::StreamExt;

use blockprod::{rpc::BlockProductionRpcClient, TimestampSearchData};
use chainstate::{rpc::ChainstateRpcClient, ChainInfo};
use common::{
    address::Address,
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        Block, Currency, DelegationId, Destination, GenBlock, OrderId, PoolId, RpcOrderInfo,
        SignedTransaction, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{time::Time, Amount, BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::EndToEndPublicKey;
use mempool::{
    rpc::MempoolRpcClient, rpc_event::RpcEvent, tx_accumulator::PackingStrategy,
    tx_options::TxOptionsOverrides, FeeRate,
};
use p2p::{
    interface::types::ConnectedPeer,
    rpc::P2pRpcClient,
    types::{bannable_address::BannableAddress, peer_id::PeerId, socket_address::SocketAddress},
};
use serialization::hex_encoded::HexEncoded;
use utils_networking::IpOrSocketAddress;
use wallet_types::wallet_type::WalletControllerMode;

use crate::node_traits::{MempoolEvent, MempoolEvents, NodeInterface};

use super::{NodeRpcClient, NodeRpcError};

#[async_trait::async_trait]
impl NodeInterface for NodeRpcClient {
    type Error = NodeRpcError;

    async fn is_cold_wallet_node(&self) -> WalletControllerMode {
        WalletControllerMode::Hot
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        ChainstateRpcClient::info(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        ChainstateRpcClient::get_block(&*self.rpc_client, block_id)
            .await
            .map_err(NodeRpcError::ResponseError)
            .map(|block_opt| block_opt.map(HexEncoded::take))
    }

    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        ChainstateRpcClient::get_mainchain_blocks(&*self.rpc_client, from, max_count)
            .await
            .map_err(NodeRpcError::ResponseError)
            .map(|blocks| blocks.into_iter().map(HexEncoded::take).collect())
    }

    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        ChainstateRpcClient::get_block_ids_as_checkpoints(
            &*self.rpc_client,
            start_height,
            end_height,
            step,
        )
        .await
        .map_err(NodeRpcError::ResponseError)
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        ChainstateRpcClient::best_block_id(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_best_block_height(&self) -> Result<common::primitives::BlockHeight, Self::Error> {
        ChainstateRpcClient::best_block_height(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        ChainstateRpcClient::block_id_at_height(&*self.rpc_client, height)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        ChainstateRpcClient::last_common_ancestor_by_id(
            &*self.rpc_client,
            first_block,
            second_block,
        )
        .await
        .map_err(NodeRpcError::ResponseError)
    }

    async fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        let pool_address = Address::new(&self.chain_config, pool_id)?;
        ChainstateRpcClient::stake_pool_balance(&*self.rpc_client, pool_address.into())
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_staker_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        let pool_address = Address::new(&self.chain_config, pool_id)?;
        ChainstateRpcClient::staker_balance(&*self.rpc_client, pool_address.into())
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_pool_decommission_destination(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<Destination>, Self::Error> {
        let pool_address = Address::new(&self.chain_config, pool_id)?;
        let dest_as_address = ChainstateRpcClient::pool_decommission_destination(
            &*self.rpc_client,
            pool_address.into(),
        )
        .await
        .map_err(NodeRpcError::ResponseError)?;

        Ok(dest_as_address.map(|addr| addr.decode_object(&self.chain_config)).transpose()?)
    }

    async fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let pool_address = Address::new(&self.chain_config, pool_id)?.into();
        let delegation_address = Address::new(&self.chain_config, delegation_id)?.into();
        ChainstateRpcClient::delegation_share(&*self.rpc_client, pool_address, delegation_address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_token_info(&self, token_id: TokenId) -> Result<Option<RPCTokenInfo>, Self::Error> {
        let token_id = Address::new(&self.chain_config, token_id)?.into();
        ChainstateRpcClient::token_info(&*self.rpc_client, token_id)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_tokens_info(
        &self,
        token_ids: BTreeSet<TokenId>,
    ) -> Result<Vec<RPCTokenInfo>, Self::Error> {
        let token_ids = token_ids
            .into_iter()
            .map(|token_id| {
                Ok::<_, Self::Error>(Address::new(&self.chain_config, token_id)?.into())
            })
            .collect::<Result<_, _>>()?;
        ChainstateRpcClient::tokens_info(&*self.rpc_client, token_ids)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_order_info(&self, order_id: OrderId) -> Result<Option<RpcOrderInfo>, Self::Error> {
        let order_id = Address::new(&self.chain_config, order_id)?.into();
        ChainstateRpcClient::order_info(&*self.rpc_client, order_id)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_orders_info_by_currencies(
        &self,
        ask_currency: Option<Currency>,
        give_currency: Option<Currency>,
    ) -> Result<BTreeMap<OrderId, RpcOrderInfo>, Self::Error> {
        ChainstateRpcClient::orders_info_by_currencies(
            &*self.rpc_client,
            ask_currency
                .map(|currency| currency.to_rpc_currency(&self.chain_config))
                .transpose()?,
            give_currency
                .map(|currency| currency.to_rpc_currency(&self.chain_config))
                .transpose()?,
        )
        .await
        .map_err(NodeRpcError::ResponseError)
    }

    async fn blockprod_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error> {
        BlockProductionRpcClient::e2e_public_key(&*self.rpc_client)
            .await
            .map(HexEncoded::take)
            .map_err(NodeRpcError::ResponseError)
    }

    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        public_key: EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        let transactions = transactions.into_iter().map(HexEncoded::new).collect::<Vec<_>>();
        BlockProductionRpcClient::generate_block_e2e(
            &*self.rpc_client,
            encrypted_input_data,
            public_key.into(),
            transactions,
            transaction_ids,
            packing_strategy,
        )
        .await
        .map(HexEncoded::take)
        .map_err(NodeRpcError::ResponseError)
    }

    async fn collect_timestamp_search_data(
        &self,
        pool_id: PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, Self::Error> {
        BlockProductionRpcClient::collect_timestamp_search_data(
            &*self.rpc_client,
            pool_id,
            min_height,
            max_height,
            seconds_to_check_for_height,
            all_timestamps_between_blocks,
        )
        .await
        .map(HexEncoded::take)
        .map_err(NodeRpcError::ResponseError)
    }

    async fn generate_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        let transactions = transactions.into_iter().map(HexEncoded::new).collect::<Vec<_>>();
        BlockProductionRpcClient::generate_block(
            &*self.rpc_client,
            input_data.into(),
            transactions,
            transaction_ids,
            packing_strategy,
        )
        .await
        .map(HexEncoded::take)
        .map_err(NodeRpcError::ResponseError)
    }

    async fn submit_block(&self, block: Block) -> Result<(), Self::Error> {
        ChainstateRpcClient::submit_block(&*self.rpc_client, block.into())
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn submit_transaction(
        &self,
        tx: SignedTransaction,
        options: TxOptionsOverrides,
    ) -> Result<(), Self::Error> {
        let status = P2pRpcClient::submit_transaction(&*self.rpc_client, tx.into(), options)
            .await
            .map_err(NodeRpcError::ResponseError)?;
        Ok(status)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        node_lib::rpc::NodeRpcClient::shutdown(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error> {
        P2pRpcClient::enable_networking(&*self.rpc_client, enable)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        node_lib::rpc::NodeRpcClient::version(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_connect(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        P2pRpcClient::connect(&*self.rpc_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        P2pRpcClient::disconnect(&*self.rpc_client, peer_id)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_list_banned(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        P2pRpcClient::list_banned(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_ban(
        &self,
        address: BannableAddress,
        duration: Duration,
    ) -> Result<(), Self::Error> {
        P2pRpcClient::ban(&*self.rpc_client, address, duration)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_unban(&self, address: BannableAddress) -> Result<(), Self::Error> {
        P2pRpcClient::unban(&*self.rpc_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_list_discouraged(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        P2pRpcClient::list_discouraged(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_undiscourage(&self, address: BannableAddress) -> Result<(), Self::Error> {
        P2pRpcClient::undiscourage(&*self.rpc_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        P2pRpcClient::get_peer_count(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        P2pRpcClient::get_connected_peers(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_get_reserved_nodes(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        P2pRpcClient::get_reserved_nodes(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_add_reserved_node(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        P2pRpcClient::add_reserved_node(&*self.rpc_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_remove_reserved_node(
        &self,
        address: IpOrSocketAddress,
    ) -> Result<(), Self::Error> {
        P2pRpcClient::remove_reserved_node(&*self.rpc_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn mempool_get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Self::Error> {
        MempoolRpcClient::get_fee_rate(&*self.rpc_client, in_top_x_mb)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        MempoolRpcClient::get_fee_rate_points(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn mempool_get_transaction(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, Self::Error> {
        MempoolRpcClient::get_transaction(&*self.rpc_client, tx_id)
            .await
            .map_err(NodeRpcError::ResponseError)
            .map(|opt| opt.map(|resp| resp.transaction.take()))
    }

    async fn mempool_subscribe_to_events(&self) -> Result<MempoolEvents, Self::Error> {
        let subscription = MempoolRpcClient::subscribe_to_events(&*self.rpc_client)
            .await
            .map_err(NodeRpcError::ResponseError)?;

        let subscription = subscription.filter_map(|item| {
            futures::future::ready(item.ok().and_then(|event| match event {
                RpcEvent::NewTip { .. } => None,

                RpcEvent::TransactionProcessed {
                    tx_id, successful, ..
                } => successful.then_some(MempoolEvent::NewTransaction { tx_id }),
            }))
        });
        Ok(Box::new(subscription))
    }

    async fn get_utxo(&self, outpoint: UtxoOutPoint) -> Result<Option<TxOutput>, Self::Error> {
        ChainstateRpcClient::get_utxo(&*self.rpc_client, outpoint.into())
            .await
            .map_err(NodeRpcError::ResponseError)
    }
}
