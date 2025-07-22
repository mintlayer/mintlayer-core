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

use blockprod::{BlockProductionError, BlockProductionHandle, TimestampSearchData};
use chainstate::{BlockSource, ChainInfo, ChainstateError, ChainstateHandle};
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
use mempool::{
    tx_accumulator::PackingStrategy, tx_options::TxOptionsOverrides, FeeRate, MempoolHandle,
};
use p2p::{
    error::P2pError,
    interface::types::ConnectedPeer,
    types::{bannable_address::BannableAddress, peer_id::PeerId, socket_address::SocketAddress},
    P2pHandle,
};
use serialization::hex::HexError;
use utils_networking::IpOrSocketAddress;
use wallet_types::wallet_type::WalletControllerMode;

use crate::node_traits::NodeInterface;

#[derive(Clone)]
pub struct WalletHandlesClient {
    chainstate: ChainstateHandle,
    mempool: MempoolHandle,
    block_prod: BlockProductionHandle,
    p2p: P2pHandle,
}

impl std::fmt::Debug for WalletHandlesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletHandlesClient").finish()
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum WalletHandlesClientError {
    #[error("Call error: {0}")]
    CallError(#[from] subsystem::error::CallError),
    #[error("Chainstate error: {0}")]
    Chainstate(#[from] ChainstateError),
    #[error("P2p error: {0}")]
    P2p(#[from] P2pError),
    #[error("Block production error: {0}")]
    BlockProduction(#[from] BlockProductionError),
    #[error("Decode error: {0}")]
    Hex(#[from] HexError),
    #[error("Mempool error: {0}")]
    MempoolError(#[from] mempool::error::Error),
    #[error("You cannot shutdown the node from this place")]
    AttemptedExit,
}

impl WalletHandlesClient {
    pub async fn new(
        chainstate: ChainstateHandle,
        mempool: MempoolHandle,
        block_prod: BlockProductionHandle,
        p2p: P2pHandle,
    ) -> Result<Self, WalletHandlesClientError> {
        let result = Self {
            chainstate,
            mempool,
            block_prod,
            p2p,
        };
        result.basic_start_test().await?;
        Ok(result)
    }

    async fn basic_start_test(&self) -> Result<(), WalletHandlesClientError> {
        // Call an arbitrary function to make sure that connection is established
        let _best_block = self.chainstate.call(move |this| this.get_best_block_id()).await??;

        Ok(())
    }
}

#[async_trait::async_trait]
impl NodeInterface for WalletHandlesClient {
    type Error = WalletHandlesClientError;

    async fn is_cold_wallet_node(&self) -> WalletControllerMode {
        WalletControllerMode::Hot
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        let result = self.chainstate.call(move |this| this.info()).await??;
        Ok(result)
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_best_block_id()).await??;
        Ok(result)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_block(block_id)).await??;
        Ok(result)
    }

    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        let blocks = self
            .chainstate
            .call(move |this| this.get_mainchain_blocks(from, max_count))
            .await??;
        Ok(blocks)
    }

    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        let block_ids = self
            .chainstate
            .call(move |this| this.get_block_ids_as_checkpoints(start_height, end_height, step))
            .await??;
        Ok(block_ids)
    }

    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_best_block_height()).await??;
        Ok(result)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_block_id_from_height(&height))
            .await??;
        Ok(result)
    }

    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.last_common_ancestor_by_id(&first_block, &second_block))
            .await??;
        Ok(result)
    }

    async fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        let result =
            self.chainstate.call(move |this| this.get_stake_pool_balance(pool_id)).await??;
        Ok(result)
    }

    async fn get_staker_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_stake_pool_data(pool_id))
            .await??
            .map(|data| data.staker_balance())
            .transpose()
            .map_err(|_| {
                ChainstateError::FailedToReadProperty(
                    chainstate::PropertyQueryError::StakerBalanceOverflow(pool_id),
                )
            })?;
        Ok(result)
    }

    async fn get_pool_decommission_destination(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<Destination>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_stake_pool_data(pool_id))
            .await??
            .map(|data| data.decommission_destination().clone());
        Ok(result)
    }

    async fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_stake_pool_delegation_share(pool_id, delegation_id))
            .await??;
        Ok(result)
    }

    async fn get_token_info(&self, token_id: TokenId) -> Result<Option<RPCTokenInfo>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_token_info_for_rpc(token_id))
            .await??;
        Ok(result)
    }

    async fn get_order_info(&self, order_id: OrderId) -> Result<Option<RpcOrderInfo>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_order_info_for_rpc(order_id))
            .await??;
        Ok(result)
    }

    async fn blockprod_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error> {
        let result = self.block_prod.call_async_mut(move |this| this.e2e_public_key()).await?;

        Ok(result)
    }

    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        public_key: EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        let block = self
            .block_prod
            .call_async_mut(move |this| {
                this.generate_block_e2e(
                    encrypted_input_data,
                    public_key,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
            })
            .await??;

        Ok(block)
    }

    async fn collect_timestamp_search_data(
        &self,
        pool_id: PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, Self::Error> {
        let search_data = self
            .block_prod
            .call_async_mut(move |this| {
                this.collect_timestamp_search_data(
                    pool_id,
                    min_height,
                    max_height,
                    seconds_to_check_for_height,
                    all_timestamps_between_blocks,
                )
            })
            .await??;

        Ok(search_data)
    }

    async fn generate_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        let block = self
            .block_prod
            .call_async_mut(move |this| {
                this.generate_block(input_data, transactions, transaction_ids, packing_strategy)
            })
            .await??;

        Ok(block)
    }

    async fn submit_block(&self, block: Block) -> Result<(), Self::Error> {
        self.chainstate
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await??;
        Ok(())
    }

    async fn get_utxo(
        &self,
        outpoint: common::chain::UtxoOutPoint,
    ) -> Result<Option<common::chain::TxOutput>, Self::Error> {
        let output = self
            .chainstate
            .call_mut(move |this| this.utxo(&outpoint))
            .await??
            .map(|utxo| utxo.take_output());
        Ok(output)
    }

    async fn submit_transaction(
        &self,
        tx: SignedTransaction,
        options: TxOptionsOverrides,
    ) -> Result<(), Self::Error> {
        Ok(self
            .p2p
            .call_async_mut(move |this| this.submit_transaction(tx, options))
            .await??)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        Err(WalletHandlesClientError::AttemptedExit)
    }
    async fn node_enable_networking(&self, enable: bool) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.enable_networking(enable)).await??;
        Ok(())
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        Ok(env!("CARGO_PKG_VERSION").into())
    }

    async fn p2p_connect(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.connect(address)).await??;
        Ok(())
    }
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.disconnect(peer_id)).await??;
        Ok(())
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        let count = self.p2p.call_async(move |this| this.get_peer_count()).await??;
        Ok(count)
    }

    async fn p2p_list_banned(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        let list = self.p2p.call_async(move |this| this.list_banned()).await??;
        Ok(list)
    }
    async fn p2p_ban(
        &self,
        address: BannableAddress,
        duration: Duration,
    ) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.ban(address, duration)).await??;
        Ok(())
    }
    async fn p2p_unban(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.unban(address)).await??;
        Ok(())
    }

    async fn p2p_list_discouraged(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        let list = self.p2p.call_async(move |this| this.list_discouraged()).await??;
        Ok(list)
    }
    async fn p2p_undiscourage(&self, address: BannableAddress) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.undiscourage(address)).await??;
        Ok(())
    }

    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        let peers = self.p2p.call_async(move |this| this.get_connected_peers()).await??;
        Ok(peers)
    }
    async fn p2p_get_reserved_nodes(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        let peers = self.p2p.call_async(move |this| this.get_reserved_nodes()).await??;
        Ok(peers)
    }
    async fn p2p_add_reserved_node(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.add_reserved_node(address)).await??;
        Ok(())
    }
    async fn p2p_remove_reserved_node(
        &self,
        address: IpOrSocketAddress,
    ) -> Result<(), Self::Error> {
        self.p2p
            .call_async_mut(move |this| this.remove_reserved_node(address))
            .await??;
        Ok(())
    }

    async fn mempool_get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Self::Error> {
        let res = self.mempool.call(move |this| this.get_fee_rate(in_top_x_mb)).await?;
        Ok(res)
    }

    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        // MIN(1) + 9 = 10, to keep it as const
        const NUM_POINTS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(9);
        let res = self.mempool.call(move |this| this.get_fee_rate_points(NUM_POINTS)).await??;
        Ok(res)
    }
}
