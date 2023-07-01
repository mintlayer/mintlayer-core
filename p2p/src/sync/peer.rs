// Copyright (c) 2022 RBB S.r.l
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
    collections::{BTreeSet, VecDeque},
    mem,
    time::Duration,
};

use itertools::Itertools;
use tokio::{
    sync::mpsc::{Receiver, UnboundedSender},
    time::MissedTickBehavior,
};

use chainstate::{
    ban_score::BanScore, chainstate_interface::ChainstateInterface, BlockError, BlockIndex,
    BlockSource, ChainstateError, Locator,
};
use common::{
    chain::{block::signed_block_header::SignedBlockHeader, Block, ChainConfig, Transaction},
    primitives::{Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{
    error::{Error as MempoolError, MempoolPolicyError},
    MempoolHandle,
};
use utils::atomics::AcqRelAtomicBool;
use utils::const_value::ConstValue;
use utils::sync::Arc;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    message::{
        BlockListRequest, BlockResponse, HeaderList, HeaderListRequest, SyncMessage,
        TransactionResponse,
    },
    net::{
        types::services::{Service, Services},
        NetworkingService,
    },
    sync::types::PeerActivity,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, PeerManagerEvent, Result,
};

// TODO: Take into account the chain work when syncing.
/// A peer context.
///
/// Syncing logic runs in a separate task for each peer.
pub struct Peer<T: NetworkingService> {
    id: ConstValue<PeerId>,
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    mempool_handle: MempoolHandle,
    peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,
    messaging_handle: T::MessagingHandle,
    sync_rx: Receiver<SyncMessage>,
    is_initial_block_download: Arc<AcqRelAtomicBool>,
    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    known_headers: Vec<SignedBlockHeader>,
    /// A list of blocks that we requested from this peer.
    requested_blocks: BTreeSet<Id<Block>>,
    /// A queue of the blocks requested this peer.
    blocks_queue: VecDeque<Id<Block>>,
    /// The index of the best known block of a peer.
    best_known_block: Option<BlockIndex>,
    // TODO: Add a timer to remove entries.
    /// A list of transactions that have been announced by this peer. An entry is added when the
    /// identifier is announced and removed when the actual transaction or not found response is received.
    announced_transactions: BTreeSet<Id<Transaction>>,
    /// A number of consecutive unconnected headers received from a peer. This counter is reset
    /// after receiving a valid header.
    unconnected_headers: usize,
    /// Last activity with the peer. For example, when we expect blocks from a peer, we can mark
    /// the peer with `PeerActivity::ExpectingBlocks`. We can use this information to, for example,
    /// disconnect the peer in case we haven't received expected data within a certain time period.
    last_activity: PeerActivity,
    time_getter: TimeGetter,
}

impl<T> Peer<T>
where
    T: NetworkingService,
    T::MessagingHandle: MessagingService,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PeerId,
        remote_services: Services,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        mempool_handle: MempoolHandle,
        peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,
        sync_rx: Receiver<SyncMessage>,
        messaging_handle: T::MessagingHandle,
        is_initial_block_download: Arc<AcqRelAtomicBool>,
        time_getter: TimeGetter,
    ) -> Self {
        let local_services: Services = (*p2p_config.node_type).into();
        let common_services = local_services & remote_services;

        Self {
            id: id.into(),
            chain_config,
            p2p_config,
            common_services,
            chainstate_handle,
            mempool_handle,
            peer_manager_sender,
            messaging_handle,
            sync_rx,
            is_initial_block_download,
            known_headers: Vec::new(),
            requested_blocks: BTreeSet::new(),
            blocks_queue: VecDeque::new(),
            best_known_block: None,
            announced_transactions: BTreeSet::new(),
            unconnected_headers: 0,
            last_activity: PeerActivity::Pending,
            time_getter,
        }
    }

    /// Returns an identifier of the peer associated with this task.
    pub fn id(&self) -> PeerId {
        *self.id
    }

    pub async fn run(&mut self) {
        match self.main_loop().await {
            // The unexpected "channel closed" error will be handled by the sync manager.
            Ok(()) | Err(P2pError::ChannelClosed) => {}
            Err(e) => panic!("{} peer task failed: {e:?}", self.id()),
        }
    }

    async fn main_loop(&mut self) -> Result<()> {
        let mut stalling_interval = tokio::time::interval(*self.p2p_config.sync_stalling_timeout);
        stalling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick completes immediately. Since we are dealing with a stalling check, we skip
        // the first tick.
        stalling_interval.tick().await;

        if self.common_services.has_service(Service::Blocks) {
            self.request_headers().await?;
        }

        loop {
            tokio::select! {
                message = self.sync_rx.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                block_to_send_to_peer = async { self.blocks_queue.pop_front().expect("The block queue is empty") }, if !self.blocks_queue.is_empty() => {
                    self.send_block(block_to_send_to_peer).await?;
                }

                _ = stalling_interval.tick(), if !matches!(self.last_activity, PeerActivity::Pending) => {}
            }

            // Run on each loop iteration, so it's easier to test
            if let PeerActivity::ExpectingHeaderList { time }
            | PeerActivity::ExpectingBlocks { time } = self.last_activity
            {
                self.handle_stalling_interval(time).await?;
            }
        }
    }

    async fn request_headers(&mut self) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        debug_assert!(locator.len() <= *self.p2p_config.msg_max_locator_count);

        log::trace!("Sending header list request to {} peer", self.id());
        self.messaging_handle.send_message(
            self.id(),
            SyncMessage::HeaderListRequest(HeaderListRequest::new(locator)),
        )?;

        self.last_activity = PeerActivity::ExpectingHeaderList {
            time: self.time_getter.get_time(),
        };

        Ok(())
    }

    async fn handle_message(&mut self, message: SyncMessage) -> Result<()> {
        let res = match message {
            SyncMessage::HeaderListRequest(r) => self.handle_header_request(r.into_locator()).await,
            SyncMessage::BlockListRequest(r) => self.handle_block_request(r.into_block_ids()).await,
            SyncMessage::HeaderList(l) => self.handle_header_list(l.into_headers()).await,
            SyncMessage::BlockResponse(r) => self.handle_block_response(r.into_block()).await,
            SyncMessage::NewTransaction(id) => self.handle_transaction_announcement(id).await,
            SyncMessage::TransactionRequest(id) => self.handle_transaction_request(id).await,
            SyncMessage::TransactionResponse(tx) => self.handle_transaction_response(tx).await,
        };
        Self::handle_result(&self.peer_manager_sender, self.id(), res).await
    }

    /// Processes a header request by sending requested data to the peer.
    async fn handle_header_request(&mut self, locator: Locator) -> Result<()> {
        log::debug!("Headers request from peer {}", self.id());

        if locator.len() > *self.p2p_config.msg_max_locator_count {
            return Err(P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(
                locator.len(),
                *self.p2p_config.msg_max_locator_count,
            )));
        }
        log::trace!("locator: {locator:#?}");

        if self.is_initial_block_download.load() {
            // TODO: Check if a peer has permissions to ask for headers during the initial block download.
            log::debug!("Ignoring headers request because the node is in initial block download");
            return Ok(());
        }

        let limit = *self.p2p_config.msg_header_count_limit;
        let headers = self.chainstate_handle.call(move |c| c.get_headers(locator, limit)).await??;
        debug_assert!(headers.len() <= limit);
        self.messaging_handle
            .send_message(self.id(), SyncMessage::HeaderList(HeaderList::new(headers)))
    }

    /// Processes the blocks request.
    async fn handle_block_request(&mut self, block_ids: Vec<Id<Block>>) -> Result<()> {
        utils::ensure!(
            !block_ids.is_empty(),
            P2pError::ProtocolError(ProtocolError::ZeroBlocksInRequest)
        );

        log::debug!(
            "Blocks request from peer {}: {}-{} ({})",
            self.id(),
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );

        if self.is_initial_block_download.load() {
            log::debug!("Ignoring blocks request because the node is in initial block download");
            return Ok(());
        }

        // Check that a peer doesn't exceed the blocks limit.
        self.p2p_config
            .max_request_blocks_count
            .checked_sub(block_ids.len())
            .and_then(|n| n.checked_sub(self.blocks_queue.len()))
            .ok_or(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(
                    block_ids.len() + self.blocks_queue.len(),
                    *self.p2p_config.max_request_blocks_count,
                ),
            ))?;
        log::trace!("Requested block ids: {block_ids:#?}");

        // Check that all the blocks are known and haven't been already requested.
        let ids = block_ids.clone();
        let best_known_block = self.best_known_block.clone();
        self.chainstate_handle
            .call(move |c| {
                // Check that all blocks are known. Skip the first block as it has already checked.
                for id in ids {
                    let index = c.get_block_index(&id)?.ok_or(P2pError::ProtocolError(
                        ProtocolError::UnknownBlockRequested(id),
                    ))?;

                    if let Some(ref best_known_block) = best_known_block {
                        if index.block_height() <= best_known_block.block_height() {
                            // This can be normal in case of reorg, check if the block id is the same.
                            let known_block_id = c
                                .get_block_id_from_height(&best_known_block.block_height())?
                                // This should never fail because we have a block for this height.
                                .expect("Unable to get block id from height");
                            if &known_block_id == best_known_block.block_id() {
                                return Err(P2pError::ProtocolError(
                                    ProtocolError::DuplicatedBlockRequest(id),
                                ));
                            }
                        }
                    }
                }

                Result::<_>::Ok(())
            })
            .await??;

        // A peer can ignore the headers request if it is in the initial block download state.
        // Assume this is the case if it asks us for blocks.
        self.last_activity = PeerActivity::Pending;

        self.blocks_queue.extend(block_ids.into_iter());

        Ok(())
    }

    async fn handle_header_list(&mut self, headers: Vec<SignedBlockHeader>) -> Result<()> {
        log::debug!("Headers list from peer {}", self.id());

        if let Some(last_header) = headers.last() {
            // Delays the processing of a new block until it can be accepted by the chainstate (but not more than `max_clock_diff`).
            // This is needed to allow the local or remote node to have slightly inaccurate clocks.
            // Without it, even a 1 second difference can break block synchronization
            // because one side may see the new block as invalid.
            let block_timestamp = last_header.timestamp().as_duration_since_epoch();
            let max_block_timestamp =
                self.time_getter.get_time() + *self.chain_config.max_future_block_time_offset();
            if block_timestamp > max_block_timestamp {
                let clock_diff = max_block_timestamp - block_timestamp;
                let sleep_time = std::cmp::min(clock_diff, *self.p2p_config.max_clock_diff);
                log::debug!(
                    "Block timestamp from the future ({} seconds), peer_id: {}",
                    sleep_time.as_secs(),
                    self.id(),
                );
                tokio::time::sleep(sleep_time).await;
            }
        }

        if !self.known_headers.is_empty() {
            // The headers list contains exactly one header when a new block is announced.
            if headers.len() == 1 {
                // We are already requesting blocks from the peer and will download a new one as
                // part of that process.
                return Ok(());
            }

            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "Headers list".to_owned(),
            )));
        }

        if headers.len() > *self.p2p_config.msg_header_count_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    *self.p2p_config.msg_header_count_limit,
                ),
            ));
        }
        log::trace!("Received headers: {headers:#?}");

        // The empty headers list means that the peer doesn't have more blocks.
        if headers.is_empty() {
            // We don't need anything from this peer unless we are still receiving blocks.
            if self.requested_blocks.is_empty() {
                self.last_activity = PeerActivity::Pending;
            }

            return Ok(());
        }

        // Each header must be connected to the previous one.
        if !headers
            .iter()
            .tuple_windows()
            .all(|(left, right)| &left.get_id() == right.prev_block_id())
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        // The first header must be connected to a known block.
        let prev_id = *headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .prev_block_id();
        if self
            .chainstate_handle
            .call(move |c| c.get_gen_block_index(&prev_id))
            .await??
            .is_none()
        {
            // It is possible to receive a new block announcement that isn't connected to our chain.
            if headers.len() == 1 {
                // In order to prevent spam from malicious peers we have the `unconnected_headers`
                // counter.
                self.unconnected_headers += 1;
                log::debug!(
                    "Peer {} sent {} unconnected headers",
                    self.id(),
                    self.unconnected_headers
                );
                if self.unconnected_headers <= *self.p2p_config.max_unconnected_headers {
                    self.request_headers().await?;
                    return Ok(());
                }
            }

            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        let is_max_headers = headers.len() == *self.p2p_config.msg_header_count_limit;
        let headers = self
            .chainstate_handle
            .call(|c| c.filter_already_existing_blocks(headers))
            .await??;
        if headers.is_empty() {
            // A peer can have more headers if we have received the maximum amount of them.
            if is_max_headers {
                self.request_headers().await?;
            } else {
                // Since we know all the blocks the peer knows, we expect no further data and mark
                // the peer activity as pending.
                self.last_activity = PeerActivity::Pending;
            }
            return Ok(());
        }

        // Only the first header can be checked with the `preliminary_header_check` function.
        let first_header = headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .clone();
        self.chainstate_handle
            .call(|c| c.preliminary_header_check(first_header))
            .await??;
        self.unconnected_headers = 0;

        self.request_blocks(headers)
    }

    async fn handle_block_response(&mut self, block: Block) -> Result<()> {
        log::debug!("Block ({}) from peer {}", block.get_id(), self.id());

        if self.requested_blocks.take(&block.get_id()).is_none() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "block response".to_owned(),
            )));
        }

        let block = self.chainstate_handle.call(|c| c.preliminary_block_check(block)).await??;
        let peer_id = self.id();
        match self
            .chainstate_handle
            .call_mut(move |c| {
                // If the block already exists in the block tree, return the existing block index.
                // It's used to prevent chainstate from printing "Block already exists" errors.
                if let Some(block_index) = c.get_block_index(&block.get_id())? {
                    log::debug!(
                        "Peer {} sent a block that already exists ({})",
                        peer_id,
                        block.get_id()
                    );
                    return Ok(Some(block_index));
                }
                c.process_block(block, BlockSource::Peer)
            })
            .await?
        {
            Ok(_) => Ok(()),
            // It is OK to receive an already processed block
            // This should not happen because of the `get_block_index` check above.
            Err(ChainstateError::ProcessBlockError(BlockError::BlockAlreadyExists(_))) => Ok(()),
            Err(e) => Err(e),
        }?;

        if self.requested_blocks.is_empty() {
            if self.known_headers.is_empty() {
                // Request more headers.
                self.request_headers().await?;
            } else {
                // Download remaining blocks.
                let headers = mem::take(&mut self.known_headers);
                self.request_blocks(headers)?;
            }
        } else {
            // We expect additional blocks from the peer. Update the timestamp we received the
            // current one.
            self.last_activity = PeerActivity::ExpectingBlocks {
                time: self.time_getter.get_time(),
            };
        }

        Ok(())
    }

    async fn handle_transaction_request(&mut self, id: Id<Transaction>) -> Result<()> {
        if !self.common_services.has_service(Service::Transactions) {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "A transaction request is received, but this node doesn't have the corresponding service".to_owned(),
            )));
        }

        let tx = self.mempool_handle.call(move |m| m.transaction(&id)).await?;
        let res = match tx {
            Some(tx) => TransactionResponse::Found(tx),
            None => TransactionResponse::NotFound(id),
        };

        self.messaging_handle
            .send_message(self.id(), SyncMessage::TransactionResponse(res))?;

        Ok(())
    }

    async fn handle_transaction_response(&mut self, resp: TransactionResponse) -> Result<()> {
        let (id, tx) = match resp {
            TransactionResponse::NotFound(id) => (id, None),
            TransactionResponse::Found(tx) => (tx.transaction().get_id(), Some(tx)),
        };

        if self.announced_transactions.take(&id).is_none() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "Unexpected transaction response".to_owned(),
            )));
        }

        if let Some(transaction) = tx {
            super::process_incoming_transaction(
                &self.mempool_handle,
                &mut self.messaging_handle,
                transaction,
            )
            .await?;
        }

        Ok(())
    }

    // TODO: This can be optimized, see https://github.com/mintlayer/mintlayer-core/issues/829
    // for details.
    async fn handle_transaction_announcement(&mut self, tx: Id<Transaction>) -> Result<()> {
        log::debug!("Transaction announcement from {} peer: {tx}", self.id());

        if self.is_initial_block_download.load() {
            log::debug!(
                "Ignoring transaction announcement because the node is in initial block download"
            );
            return Ok(());
        }

        if !self.common_services.has_service(Service::Transactions) {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "A transaction announcement is received, but this node doesn't have the corresponding service".to_owned(),
            )));
        }

        if self.announced_transactions.len() >= *self.p2p_config.max_peer_tx_announcements {
            return Err(P2pError::ProtocolError(
                ProtocolError::TransactionAnnouncementLimitExceeded(
                    *self.p2p_config.max_peer_tx_announcements,
                ),
            ));
        }

        if self.announced_transactions.contains(&tx) {
            return Err(P2pError::ProtocolError(
                ProtocolError::DuplicatedTransactionAnnouncement(tx),
            ));
        }

        if !(self.mempool_handle.call(move |m| m.contains_transaction(&tx)).await?) {
            self.messaging_handle
                .send_message(self.id(), SyncMessage::TransactionRequest(tx))?;
            assert!(self.announced_transactions.insert(tx));
        }

        Ok(())
    }

    /// Handles a result of message processing.
    ///
    /// There are three possible types of errors:
    /// - Fatal errors will be propagated by this function effectively stopping the peer event loop.
    /// - Non-fatal errors aren't propagated, but the peer score will be increased by the
    ///   "ban score" value of the given error.
    /// - Ignored errors aren't propagated and don't affect the peer score.
    pub async fn handle_result(
        peer_manager_sender: &UnboundedSender<PeerManagerEvent<T>>,
        peer_id: PeerId,
        result: Result<()>,
    ) -> Result<()> {
        let error = match result {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };

        match error {
            // Due to the fact that p2p is split into several tasks, it is possible to send a
            // request/response after a peer is disconnected, but before receiving the disconnect
            // event. Therefore this error can be safely ignored.
            P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
            // The special handling of these mempool errors is not really necessary, because their ban score is 0
            P2pError::MempoolError(MempoolError::Policy(
                MempoolPolicyError::MempoolFull | MempoolPolicyError::TransactionAlreadyInMempool,
            )) => Ok(()),

            // A protocol error - increase the ban score of a peer if needed.
            e @ (P2pError::ProtocolError(_)
            | P2pError::MempoolError(_)
            | P2pError::ChainstateError(_)) => {
                let ban_score = e.ban_score();
                if ban_score > 0 {
                    log::info!(
                        "Adjusting the '{}' peer score by {}: {:?}",
                        peer_id,
                        ban_score,
                        e,
                    );

                    let (sender, receiver) = oneshot_nofail::channel();
                    peer_manager_sender.send(PeerManagerEvent::AdjustPeerScore(
                        peer_id, ban_score, sender,
                    ))?;
                    receiver.await?.or_else(|e| match e {
                        P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
                        e => Err(e),
                    })
                } else {
                    log::debug!(
                        "Ignoring error with the ban score of 0 for the '{}' peer: {:?}",
                        peer_id,
                        e,
                    );
                    Ok(())
                }
            }

            // Some of these errors aren't technically fatal,
            // but they shouldn't occur in the sync manager.
            e @ (P2pError::DialError(_)
            | P2pError::ConversionError(_)
            | P2pError::PeerError(_)
            | P2pError::NoiseHandshakeError(_)
            | P2pError::InvalidConfigurationValue(_)) => panic!("Unexpected error {e:?}"),

            // Fatal errors, simply propagate them to stop the sync manager.
            e @ (P2pError::ChannelClosed
            | P2pError::SubsystemFailure
            | P2pError::StorageFailure(_)
            | P2pError::InvalidStorageState(_)) => Err(e),
        }
    }

    /// Sends a block list request.
    ///
    /// The number of headers sent equals to `P2pConfig::requested_blocks_limit`, the remaining
    /// headers are stored in the peer context.
    fn request_blocks(&mut self, mut headers: Vec<SignedBlockHeader>) -> Result<()> {
        debug_assert!(self.known_headers.is_empty());

        // Remove already requested blocks.
        headers.retain(|h| !self.requested_blocks.contains(&h.get_id()));
        if headers.is_empty() {
            return Ok(());
        }

        if headers.len() > *self.p2p_config.max_request_blocks_count {
            self.known_headers = headers.split_off(*self.p2p_config.max_request_blocks_count);
        }

        let block_ids: Vec<_> = headers.into_iter().map(|h| h.get_id()).collect();
        log::debug!(
            "Request blocks from peer {}: {}-{} ({})",
            self.id(),
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );
        self.messaging_handle.send_message(
            self.id(),
            SyncMessage::BlockListRequest(BlockListRequest::new(block_ids.clone())),
        )?;
        self.requested_blocks.extend(block_ids);

        self.last_activity = PeerActivity::ExpectingBlocks {
            time: self.time_getter.get_time(),
        };

        Ok(())
    }

    async fn send_block(&mut self, id: Id<Block>) -> Result<()> {
        let (block, index) = self
            .chainstate_handle
            .call(move |c| {
                let index = c.get_block_index(&id);
                let block = c.get_block(id);
                (block, index)
            })
            .await?;
        // All requested blocks are already checked while processing `BlockListRequest`.
        let block = block?.unwrap_or_else(|| panic!("Unknown block requested: {id}"));
        self.best_known_block = index?;

        log::debug!("Sending {} block to {} peer", block.get_id(), self.id());
        self.messaging_handle.send_message(
            self.id(),
            SyncMessage::BlockResponse(BlockResponse::new(block)),
        )
    }

    async fn handle_stalling_interval(&mut self, last_activity: Duration) -> Result<()> {
        if self.time_getter.get_time() < last_activity + *self.p2p_config.sync_stalling_timeout {
            return Ok(());
        }

        // Nodes can disconnect each other if all of them are in the initial block download state,
        // but this should never occur in a normal network and can be worked around in the tests.
        let (sender, receiver) = oneshot_nofail::channel();
        log::warn!("Disconnecting peer for ignoring requests");
        self.peer_manager_sender.send(PeerManagerEvent::Disconnect(self.id(), sender))?;
        receiver.await?.or_else(|e| match e {
            P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
            e => Err(e),
        })
    }
}
