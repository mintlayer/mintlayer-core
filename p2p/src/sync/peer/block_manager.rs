// Copyright (c) 2021-2023 RBB S.r.l
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
};

use itertools::Itertools;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};

use chainstate::{chainstate_interface::ChainstateInterface, BlockIndex, BlockSource, Locator};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        Block, ChainConfig, GenBlock,
    },
    primitives::{time::Time, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use utils::const_value::ConstValue;
use utils::sync::Arc;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{P2pError, PeerError, ProtocolError, SyncError},
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    net::{
        types::services::{Service, Services},
        NetworkingService,
    },
    peer_manager_event::PeerDisconnectionDbAction,
    sync::{
        chainstate_handle::ChainstateHandle,
        peer_activity::PeerActivity,
        peer_common::{choose_peers_best_block, handle_message_processing_result},
        sync_status::PeerBlockSyncStatus,
        LocalEvent,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, PeerManagerEvent, Result,
};

// TODO: Take into account the chain work when syncing.
/// Block syncing manager.
///
/// Syncing logic runs in a separate task for each peer.
pub struct PeerBlockSyncManager<T: NetworkingService> {
    id: ConstValue<PeerId>,
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    chainstate_handle: ChainstateHandle,
    peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_msg_receiver: Receiver<BlockSyncMessage>,
    local_event_receiver: UnboundedReceiver<LocalEvent>,
    time_getter: TimeGetter,
    /// Incoming data state.
    incoming: IncomingDataState,
    /// Outgoing data state.
    outgoing: OutgoingDataState,
    /// Current activity with the peer.
    peer_activity: PeerActivity,
    /// If this is set, it means that we've sent a HeaderList to the peer with the number
    /// of headers less than the maximum. This is the signal to the peer that we have no more
    /// headers, so it may not ask us for more of them in the future.
    have_sent_all_headers: bool,
}

struct IncomingDataState {
    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    pending_headers: Vec<SignedBlockHeader>,
    /// A list of blocks that we requested from this peer.
    requested_blocks: VecDeque<Id<Block>>,
    /// The id of the best block header that we've received from the peer and that we also have.
    /// This includes headers received by any means, e.g. via HeaderList messages, as part
    /// of a locator during peer's header requests, via block responses.
    peers_best_block_that_we_have: Option<Id<GenBlock>>,
}

struct OutgoingDataState {
    /// A queue of the blocks requested by this peer.
    blocks_queue: VecDeque<Id<Block>>,
    /// The index of the best block that we've sent to the peer.
    best_sent_block: Option<BlockIndex>,
    /// The id of the best block header that we've sent to the peer.
    // Note: at this moment this field is only informational, i.e. we only print it to the log.
    best_sent_block_header: Option<Id<GenBlock>>,
}

impl<T> PeerBlockSyncManager<T>
where
    T: NetworkingService,
    T::MessagingHandle: MessagingService,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PeerId,
        common_services: Services,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: ChainstateHandle,
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        sync_msg_receiver: Receiver<BlockSyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_receiver: UnboundedReceiver<LocalEvent>,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            id: id.into(),
            chain_config,
            p2p_config,
            common_services,
            chainstate_handle,
            peer_mgr_event_sender,
            messaging_handle,
            sync_msg_receiver,
            local_event_receiver,
            time_getter,
            incoming: IncomingDataState {
                pending_headers: Vec::new(),
                requested_blocks: VecDeque::new(),
                peers_best_block_that_we_have: None,
            },
            outgoing: OutgoingDataState {
                blocks_queue: VecDeque::new(),
                best_sent_block: None,
                best_sent_block_header: None,
            },
            peer_activity: PeerActivity::new(),
            have_sent_all_headers: false,
        }
    }

    /// Returns an identifier of the peer associated with this task.
    pub fn id(&self) -> PeerId {
        *self.id
    }

    #[tracing::instrument(skip_all, name = "", fields(peer_id = %self.id()))]
    pub async fn run(&mut self) {
        match self.main_loop().await {
            // The unexpected "channel closed" error will be handled by the sync manager.
            Ok(()) | Err(P2pError::ChannelClosed) => {}
            Err(e) => panic!("{} peer task failed: {e:?}", self.id()),
        }
    }

    async fn main_loop(&mut self) -> Result<()> {
        let stalling_timeout = *self.p2p_config.sync_stalling_timeout;
        let last_sync_status = self.get_sync_status();

        if self.common_services.has_service(Service::Blocks) {
            log::debug!("Asking for headers initially");
            self.request_headers().await?;
        }

        self.handle_sync_status_change(&last_sync_status)?;

        loop {
            let last_sync_status = self.get_sync_status();

            tokio::select! {
                message = self.sync_msg_receiver.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                block_to_send_to_peer = async {
                    self.outgoing.blocks_queue.pop_front().expect("The block queue is empty")
                }, if !self.outgoing.blocks_queue.is_empty() => {
                    self.send_block(block_to_send_to_peer).await?;
                }

                event = self.local_event_receiver.recv() => {
                    let event = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_local_event(event).await?;
                }

                _ = tokio::time::sleep(stalling_timeout),
                    if self.peer_activity.earliest_expected_activity_time().is_some() => {}
            }

            self.handle_sync_status_change(&last_sync_status)?;

            // Run on each loop iteration, so it's easier to test
            self.handle_stalling_interval().await;
        }
    }

    fn get_sync_status(&self) -> PeerBlockSyncStatus {
        PeerBlockSyncStatus {
            expecting_blocks_since: self.peer_activity.expecting_blocks_since(),
        }
    }

    fn handle_sync_status_change(&self, prev_sync_status: &PeerBlockSyncStatus) -> Result<()> {
        let cur_sync_status = self.get_sync_status();

        if cur_sync_status != *prev_sync_status {
            self.peer_mgr_event_sender.send(PeerManagerEvent::PeerBlockSyncStatusUpdate {
                peer_id: self.id(),
                new_status: cur_sync_status,
            })?;
        }

        Ok(())
    }

    fn send_message(&mut self, message: BlockSyncMessage) -> Result<()> {
        self.messaging_handle.send_block_sync_message(self.id(), message)
    }

    fn send_headers(&mut self, headers: HeaderList) -> Result<()> {
        if let Some(last_header) = headers.headers().last() {
            self.outgoing.best_sent_block_header = Some(last_header.block_id().into());
        }
        self.send_message(BlockSyncMessage::HeaderList(headers))
    }

    async fn handle_new_tip(&mut self, new_tip_id: &Id<Block>) -> Result<()> {
        // This function is not supposed to be called when in IBD.
        debug_assert!(!self.chainstate_handle.is_initial_block_download().await?);

        let best_sent_block_id =
            self.outgoing.best_sent_block.as_ref().map(|index| (*index.block_id()).into());

        log::debug!(
            concat!(
                "In handle_new_tip: have_sent_all_headers = {}, ",
                "best_sent_block_header = {:?}, best_sent_block = {:?}, ",
                "peers_best_block_that_we_have = {:?}"
            ),
            self.have_sent_all_headers,
            self.outgoing.best_sent_block_header,
            best_sent_block_id,
            self.incoming.peers_best_block_that_we_have
        );

        // Note: if we haven't sent all our headers last time, the peer will ask us for more anyway,
        // so no need to send the update just now.
        // Likewise, if the peer has requested blocks, it will send another header request once
        // it gets the blocks, so no need to send the update in this case either.
        if self.have_sent_all_headers && self.outgoing.blocks_queue.is_empty() {
            debug_assert!(self.common_services.has_service(Service::Blocks));

            if self.incoming.peers_best_block_that_we_have.is_some() || best_sent_block_id.is_some()
            {
                let limit = *self.p2p_config.protocol_config.msg_header_count_limit;
                let new_tip_id = *new_tip_id;

                let block_ids: Vec<_> = self
                    .incoming
                    .peers_best_block_that_we_have
                    .iter()
                    .chain(best_sent_block_id.iter())
                    .copied()
                    .collect();

                // Obtain the headers to be sent and also the best block id, which will be
                // needed for a later check.
                let (headers, best_block_id) = self
                    .chainstate_handle
                    .call(move |c| {
                        let best_block_id = c.get_best_block_id()?;

                        let headers =
                            c.get_mainchain_headers_since_latest_fork_point(&block_ids, limit)?;
                        Ok((headers, best_block_id))
                    })
                    .await?;

                if headers.is_empty() {
                    log::debug!(
                        "Got new tip event with block id {}, but there is nothing to send",
                        new_tip_id,
                    );
                } else if best_block_id != new_tip_id {
                    // If we got here, another "new tip" event should be generated soon,
                    // so we may ignore this one (and it makes sense to ignore it to avoid sending
                    // the same header list multiple times).
                    log::debug!(
                        "Got new tip event with block id {}, but the tip has changed since then to {}",
                        new_tip_id,
                        best_block_id
                    );
                } else {
                    log::debug!("Sending header list of length {}", headers.len());
                    return self.send_headers(HeaderList::new(headers));
                }
            } else {
                // Note: if we got here, then we haven't received a single header request or
                // response from the peer yet (otherwise peers_best_block_that_we_have would be
                // set at least to the genesis). There is no point in doing anything specific here.
                log::warn!("Ignoring new tip event, because we don't know what to send");
            }
        }

        Ok(())
    }

    async fn handle_local_event(&mut self, event: LocalEvent) -> Result<()> {
        log::debug!("Handling local peer mgr event: {event:?}");

        match event {
            LocalEvent::ChainstateNewTip(new_tip_id) => self.handle_new_tip(&new_tip_id).await,
            LocalEvent::MempoolNewTx(_) => Ok(()),
        }
    }

    async fn request_headers(&mut self) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| Ok(this.get_locator()?)).await?;
        if locator.len() > *self.p2p_config.protocol_config.msg_max_locator_count {
            log::warn!(
                "Sending locator of the length {}, which exceeds the maximum length {:?}",
                locator.len(),
                self.p2p_config.protocol_config.msg_max_locator_count
            );
        }

        log::debug!("Sending header list request");
        self.send_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))?;

        self.peer_activity
            .set_expecting_headers_since(Some(self.time_getter.get_time()));

        Ok(())
    }

    async fn handle_message(&mut self, message: BlockSyncMessage) -> Result<()> {
        log::trace!("Handling block sync message from the peer: {message:?}");

        let res = match message {
            BlockSyncMessage::HeaderListRequest(r) => {
                self.handle_header_request(r.into_locator()).await
            }
            BlockSyncMessage::BlockListRequest(r) => {
                self.handle_block_request(r.into_block_ids()).await
            }
            BlockSyncMessage::HeaderList(l) => self.handle_header_list(l.into_headers()).await,
            BlockSyncMessage::BlockResponse(r) => self.handle_block_response(r.into_block()).await,

            #[cfg(test)]
            BlockSyncMessage::TestSentinel(id) => {
                self.send_message(BlockSyncMessage::TestSentinel(id))
            }
        };
        handle_message_processing_result(&self.peer_mgr_event_sender, self.id(), res).await
    }

    /// Processes a header request by sending requested data to the peer.
    async fn handle_header_request(&mut self, locator: Locator) -> Result<()> {
        log::debug!("Handling header request");

        if locator.len() > *self.p2p_config.protocol_config.msg_max_locator_count {
            return Err(P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(
                locator.len(),
                *self.p2p_config.protocol_config.msg_max_locator_count,
            )));
        }

        if self.chainstate_handle.is_initial_block_download().await? {
            log::debug!(
                "Responding with empty headers list because the node is in initial block download"
            );
            // Respond with an empty list to avoid being marked as stalled.
            // Note: sending actual headers when in IBD is in general not a good idea, because
            // we may not be on the correct chain. E.g. the current best block might be below
            // the first checkpoint, so we'd have no way of knowing that the chain is bogus.
            // And if we sent such headers to a peer that have seen a checkpointed block, it
            // would ban us.
            self.send_headers(HeaderList::new(Vec::new()))?;
            return Ok(());
        }

        // Obtain headers and also determine the new value for peers_best_block_that_we_have.
        let header_count_limit = *self.p2p_config.protocol_config.msg_header_count_limit;
        let old_peers_best_block_that_we_have = self.incoming.peers_best_block_that_we_have;
        let (headers, peers_best_block_that_we_have) = self
            .chainstate_handle
            .call(move |c| {
                let headers = c.get_mainchain_headers_by_locator(&locator, header_count_limit)?;
                let peers_best_block_that_we_have = if let Some(header) = headers.first() {
                    // If headers obtained from the locator are non-empty, the parent of
                    // the first one represents the locator's latest block that is present in
                    // this node's main chain (or the genesis).
                    let last_common_block_id = *header.prev_block_id();
                    choose_peers_best_block(
                        c,
                        old_peers_best_block_that_we_have,
                        Some(last_common_block_id),
                    )?
                } else {
                    // If headers are empty, the peer already has our best block.
                    Some(c.get_best_block_id()?)
                };

                Ok((headers, peers_best_block_that_we_have))
            })
            .await?;
        debug_assert!(headers.len() <= header_count_limit);
        self.incoming.peers_best_block_that_we_have = peers_best_block_that_we_have;

        // Sending a below-the-max amount of headers is a signal to the peer that we've sent
        // all headers that were available at the moment.
        self.have_sent_all_headers = headers.len() < header_count_limit;

        self.send_headers(HeaderList::new(headers))
    }

    /// Processes the blocks request.
    async fn handle_block_request(&mut self, block_ids: Vec<Id<Block>>) -> Result<()> {
        utils::ensure!(
            !block_ids.is_empty(),
            P2pError::ProtocolError(ProtocolError::ZeroBlocksInRequest)
        );

        log::debug!(
            "Handling block request: {}-{} ({})",
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );

        if self.chainstate_handle.is_initial_block_download().await? {
            // Note: currently this is not a normal situation, because a node in IBD wouldn't
            // send block headers to the peer in the first place, which means that the peer won't
            // be able to ask it for blocks.
            // TODO: return an error with a non-zero ban score instead?
            log::warn!(
                "The node is in initial block download, but the peer is asking us for blocks"
            );
            return Ok(());
        }

        // Check that a peer doesn't exceed the blocks limit.
        self.p2p_config
            .protocol_config
            .max_request_blocks_count
            .checked_sub(block_ids.len())
            .and_then(|n| n.checked_sub(self.outgoing.blocks_queue.len()))
            .ok_or(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(
                    block_ids.len() + self.outgoing.blocks_queue.len(),
                    *self.p2p_config.protocol_config.max_request_blocks_count,
                ),
            ))?;

        // Check that all the blocks are known and haven't been already requested.
        // First check self.outgoing.blocks_queue
        let already_requested_blocks: BTreeSet<_> = self.outgoing.blocks_queue.iter().collect();
        let doubly_requested_id = block_ids.iter().find(|id| already_requested_blocks.contains(id));
        if let Some(id) = doubly_requested_id {
            return Err(P2pError::ProtocolError(
                ProtocolError::DuplicatedBlockRequest(*id),
            ));
        }

        // Then check the chainstate
        let ids = block_ids.clone();
        let best_sent_block = self.outgoing.best_sent_block.clone();
        self.chainstate_handle
            .call(move |c| {
                for id in ids {
                    // Note: in the future, when/if we implement block purging, it may be possible for a previously
                    // existing block (and therefore its BlockIndex) not to exist anymore; if this happens, the
                    // following check will fail without peer's fault. (But this situation should be rare, so we
                    // probably won't care about it anyway, because its impact - erroneously discourage/or be discouraged
                    // by a peer - is low.)
                    // Also see a similar note in send_block.
                    let index = c.get_block_index_for_persisted_block(&id)?.ok_or(
                        P2pError::ProtocolError(ProtocolError::UnknownBlockRequested(id)),
                    )?;

                    if let Some(ref best_sent_block) = best_sent_block {
                        if index.block_height() <= best_sent_block.block_height() {
                            // This can be normal in case of reorg; ensure that the mainchain block
                            // at best_sent_block's height has a different id.
                            // Note that mainchain could have become shorter due to blocks
                            // invalidation, so no block at that height may be present at all.
                            if let Some(mainchain_block_id_at_height) =
                                c.get_block_id_from_height(&best_sent_block.block_height())?
                            {
                                if &mainchain_block_id_at_height == best_sent_block.block_id() {
                                    return Err(P2pError::ProtocolError(
                                        ProtocolError::DuplicatedBlockRequest(id),
                                    ));
                                }
                            }
                        }
                    }
                }

                Ok(())
            })
            .await?;

        // Note: we've already checked that the total number of elements in the queue
        // won't exceed max_request_blocks_count.
        // TODO: we might want to overwrite the queue here instead of extending it, see
        // https://github.com/mintlayer/mintlayer-core/issues/1324
        // But note that it will complicate the requesting part, which will have to maintain
        // two versions of incoming.requested_blocks, one for the most recent request and
        // another one for the previous request(s), so that it can distinguish previously
        // requested blocks that were "cancelled" in-flight from unsolicited ones.
        self.outgoing.blocks_queue.extend(block_ids.into_iter());

        Ok(())
    }

    /// Delays the processing of a new block until it can be accepted by the chainstate (but not more than `max_clock_diff`).
    /// This is needed to allow the local or remote node to have slightly inaccurate clocks.
    /// Without it, even a 1 second difference can break block synchronization
    /// because one side may see the new block as invalid.
    // TODO: this must be removed; but at this moment this is not really possible, because
    // blockprod currently creates new blocks in the future, near the maximally allowed mark.
    // Also, see the issue #1024.
    async fn wait_for_clock_diff(
        &self,
        block_timestamp: BlockTimestamp,
        block_height: BlockHeight,
    ) {
        let max_accepted_time = (self.time_getter.get_time()
            + self.chain_config.max_future_block_time_offset(block_height))
        .expect("Both values come from this node's clock; so cannot fail");
        let max_block_timestamp = BlockTimestamp::from_time(max_accepted_time);
        if block_timestamp > max_block_timestamp {
            let block_timestamp = block_timestamp.as_duration_since_epoch();
            let max_block_timestamp = max_block_timestamp.as_duration_since_epoch();

            let clock_diff =
                block_timestamp.checked_sub(max_block_timestamp).unwrap_or_else(|| {
                    panic!(
                        "Subtracting durations for block times overflow: {} - {}",
                        block_timestamp.as_secs(),
                        max_block_timestamp.as_secs()
                    )
                });

            let sleep_time = std::cmp::min(clock_diff, self.p2p_config.effective_max_clock_diff());
            log::debug!(
                "Block timestamp from the future ({} seconds)",
                sleep_time.as_secs()
            );
            tokio::time::sleep(sleep_time).await;
        }
    }

    async fn handle_header_list(&mut self, headers: Vec<SignedBlockHeader>) -> Result<()> {
        log::debug!("Handling header list");

        self.peer_activity.set_expecting_headers_since(None);

        if headers.is_empty() {
            // The peer can send an empty list when it has got a header request but it has no new blocks.
            return Ok(());
        }

        if headers.len() > *self.p2p_config.protocol_config.msg_header_count_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    *self.p2p_config.protocol_config.msg_header_count_limit,
                ),
            ));
        }

        // Each header must be connected to the previous one.
        if !headers
            .iter()
            .tuple_windows()
            .all(|(left, right)| &left.get_id() == right.prev_block_id())
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        // The first header must be connected to the chainstate.
        let first_header_prev_id = *headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .prev_block_id();

        // Note: we require a peer to send headers starting from a block that we already have
        // in our chainstate. I.e. we don't allow:
        // 1) Basing new headers on a previously sent header, because this would give a malicious
        // peer an opportunity to flood the node with headers, potentially exhausting its memory.
        // The downside of this restriction is that the peer may have to send the same headers
        // multiple times. So, to avoid extra traffic, an honest peer should't send header updates
        // when the node is already downloading blocks. (But still, the node shouldn't punish
        // the peer for doing so, because it's possible for it to do so by accident, e.g.
        // a "new tip" event may happen on the peer's side after it has sent us the last requested
        // block but before we've asked it for more.)
        // 2) Basing new headers on a block that we've requested from the peer but that has not
        // yet been sent. This is a rather useless optimization (provided that peers don't send
        // header updates when we're downloading blocks from them, as mentioned above) that
        // would only complicate the logic.

        let first_header_prev_block_height = self
            .chainstate_handle
            // Use get_gen_block_index_for_any_block instead of get_gen_block_index_for_persisted_block
            // to avoid bailing out with the DisconnectedHeaders error early (the appropriate error will
            // be generated when checking the header later and its ban score will be bigger).
            .call(move |c| Ok(c.get_gen_block_index_for_any_block(&first_header_prev_id)?))
            .await?
            .ok_or(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders))?
            .block_height();

        let last_header = headers.last().expect("Headers shouldn't be empty");
        let last_header_height = first_header_prev_block_height
            .checked_add(headers.len() as u64)
            .expect("cannot overflow");
        self.wait_for_clock_diff(last_header.timestamp(), last_header_height).await;

        let peer_may_have_more_headers =
            headers.len() == *self.p2p_config.protocol_config.msg_header_count_limit;

        // Filter out any existing headers from "headers" and determine the new value for
        // peers_best_block_that_we_have.
        let old_peers_best_block_that_we_have = self.incoming.peers_best_block_that_we_have;
        let (new_block_headers, peers_best_block_that_we_have) = self
            .chainstate_handle
            .call(move |c| {
                let (existing_block_headers, new_block_headers) =
                    c.split_off_leading_known_headers(headers)?;
                let peers_best_block_that_we_have = choose_peers_best_block(
                    c,
                    old_peers_best_block_that_we_have,
                    existing_block_headers.last().map(|header| header.get_id().into()),
                )?;

                Ok((new_block_headers, peers_best_block_that_we_have))
            })
            .await?;

        self.incoming.peers_best_block_that_we_have = peers_best_block_that_we_have;

        if !self.incoming.requested_blocks.is_empty() {
            // We are already downloading blocks, so bail out.
            // Note that we unconditionally replace pending_headers with new_block_headers
            // even if the latter is empty (because this will just mean that the peer has reorged
            // to something similar to our mainchain, so the old pending_headers are stale now).
            self.incoming.pending_headers = new_block_headers;
            return Ok(());
        }

        if new_block_headers.is_empty() {
            if peer_may_have_more_headers {
                self.request_headers().await?;
            }
            return Ok(());
        }

        // Now use preliminary_headers_check; this can be done because the first header
        // is known to be connected to the chainstate.
        {
            let new_block_headers = new_block_headers.clone();
            self.chainstate_handle
                .call(move |c| Ok(c.preliminary_headers_check(&new_block_headers)?))
                .await?;
        }

        self.request_blocks(new_block_headers)
    }

    async fn handle_block_response(&mut self, block: Block) -> Result<()> {
        let block_id = block.get_id();
        log::debug!("Handling block response, block id = {block_id}");

        if self.incoming.requested_blocks.front() != Some(&block.get_id()) {
            let idx = self.incoming.requested_blocks.iter().position(|id| id == &block.get_id());
            // Note: we treat wrongly ordered blocks in the same way as unsolicited ones, i.e.
            // we don't remove their ids from the list.
            if idx.is_some() {
                return Err(P2pError::ProtocolError(
                    ProtocolError::BlocksReceivedInWrongOrder {
                        expected_block_id: *self
                            .incoming
                            .requested_blocks
                            .front()
                            .expect("The deque is known to be non-empty"),
                        actual_block_id: block.get_id(),
                    },
                ));
            } else {
                return Err(P2pError::ProtocolError(
                    ProtocolError::UnsolicitedBlockReceived(block.get_id()),
                ));
            }
        }

        self.incoming.requested_blocks.pop_front();

        if self.incoming.requested_blocks.is_empty() {
            self.peer_activity.set_expecting_blocks_since(None);
        } else {
            self.peer_activity.set_expecting_blocks_since(Some(self.time_getter.get_time()));
        }

        let block = self.chainstate_handle.call(|c| Ok(c.preliminary_block_check(block)?)).await?;

        // Process the block and also determine the new value for peers_best_block_that_we_have.
        let old_peers_best_block_that_we_have = self.incoming.peers_best_block_that_we_have;
        let (best_block, new_tip_received) = self
            .chainstate_handle
            .call_mut(move |c| {
                // If the block already exists in the block tree, skip it.
                let new_tip_received =
                    if c.get_block_index_for_persisted_block(&block.get_id())?.is_some() {
                        log::debug!("The peer sent a block that already exists ({block_id})");
                        false
                    } else {
                        let block_index = c.process_block(block, BlockSource::Peer)?;
                        block_index.is_some()
                    };

                let best_block = choose_peers_best_block(
                    c,
                    old_peers_best_block_that_we_have,
                    Some(block_id.into()),
                )?;

                Ok((best_block, new_tip_received))
            })
            .await?;
        self.incoming.peers_best_block_that_we_have = best_block;

        if new_tip_received {
            self.peer_mgr_event_sender.send(PeerManagerEvent::NewTipReceived {
                peer_id: self.id(),
                block_id,
            })?;
        }

        if self.incoming.requested_blocks.is_empty() {
            let headers = mem::take(&mut self.incoming.pending_headers);
            // Note: we could have received some of these blocks from another peer in the meantime,
            // so filter out any existing blocks from 'headers' first.
            // TODO: we can still request the same block from multiple peers, potentially from all
            // of them, which is sub-optimal. See https://github.com/mintlayer/mintlayer-core/issues/1323
            let headers = if headers.is_empty() {
                headers
            } else {
                self.chainstate_handle
                    .call(|c| Ok(c.split_off_leading_known_headers(headers)?))
                    .await?
                    .1
            };

            if headers.is_empty() {
                // Request more headers.
                self.request_headers().await?;
            } else {
                // Download remaining blocks.
                self.request_blocks(headers)?;
            }
        }

        Ok(())
    }

    /// Sends a block list request.
    ///
    /// The number of blocks requested equals `ProtocolConfig::max_request_blocks_count`,
    /// the remaining headers are stored in the peer context.
    fn request_blocks(&mut self, mut headers: Vec<SignedBlockHeader>) -> Result<()> {
        debug_assert!(self.incoming.pending_headers.is_empty());
        debug_assert!(self.incoming.requested_blocks.is_empty());
        debug_assert!(!headers.is_empty());

        if headers.len() > *self.p2p_config.protocol_config.max_request_blocks_count {
            self.incoming.pending_headers =
                headers.split_off(*self.p2p_config.protocol_config.max_request_blocks_count);
        }

        let block_ids: Vec<_> = headers.into_iter().map(|h| h.get_id()).collect();
        log::debug!(
            "Requesting blocks from the peer: {}-{} ({})",
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );
        self.send_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            block_ids.clone(),
        )))?;
        // Even in the hypothetical situation where the "debug_assert!(requested_blocks.is_empty())"
        // above fires, we still don't want to give the peer a chance to cause uncontrollable memory
        // allocations on the node. This is why we assign and not "extend".
        self.incoming.requested_blocks = block_ids.into();

        self.peer_activity.set_expecting_blocks_since(Some(self.time_getter.get_time()));

        Ok(())
    }

    async fn send_block(&mut self, id: Id<Block>) -> Result<()> {
        let (block, block_index) = self
            .chainstate_handle
            .call(move |c| {
                let index = c.get_block_index_for_persisted_block(&id);
                let block = c.get_block(id);
                Ok((block, index))
            })
            .await?;
        // Note: all requested blocks have already been checked for existence in handle_block_request.
        // But in the future, when/if we implement block purging, it will still be possible for a
        // block to become missing by this point. This should be a rare and low impact situation,
        // but at least we should fail gracefully here and not panic.
        // Also see a similar note in handle_block_request.
        let block = block?.ok_or(SyncError::BlockDataMissingInSendBlock(id))?;
        let block_index = block_index?.ok_or(SyncError::BlockIndexMissingInSendBlock(id))?;

        let old_best_sent_block_id = self.outgoing.best_sent_block.as_ref().map(|idx| {
            let id: Id<GenBlock> = (*idx.block_id()).into();
            id
        });
        let new_best_sent_block_id = self
            .chainstate_handle
            .call(move |c| choose_peers_best_block(c, old_best_sent_block_id, Some(id.into())))
            .await?;

        if new_best_sent_block_id == Some(id.into()) {
            self.outgoing.best_sent_block = Some(block_index);
        }

        log::debug!("Sending block with id = {} to the peer", block.get_id());
        self.send_message(BlockSyncMessage::BlockResponse(BlockResponse::new(block)))
    }

    async fn disconnect_if_stalling(&mut self) -> Result<()> {
        let cur_time = self.time_getter.get_time();
        let is_stalling = |activity_time: Option<Time>| {
            cur_time
                >= (activity_time.unwrap_or(cur_time) + *self.p2p_config.sync_stalling_timeout)
                    .expect("All from local clock. Cannot fail.")
        };
        let headers_req_stalling = is_stalling(self.peer_activity.expecting_headers_since());
        let blocks_req_stalling = is_stalling(self.peer_activity.expecting_blocks_since());

        if !(headers_req_stalling || blocks_req_stalling) {
            return Ok(());
        }

        // Nodes can disconnect each other if all of them are in the initial block download state,
        // but this should never occur in a normal network and can be worked around in the tests.
        let (sender, receiver) = oneshot_nofail::channel();
        log::warn!("Disconnecting the peer for ignoring requests, headers_req_stalling = {}, blocks_req_stalling = {}",
            headers_req_stalling, blocks_req_stalling);
        self.peer_mgr_event_sender.send(PeerManagerEvent::Disconnect(
            self.id(),
            PeerDisconnectionDbAction::Keep,
            Some(DisconnectionReason::SyncRequestsIgnored),
            sender,
        ))?;
        receiver.await?.or_else(|e| match e {
            P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
            e => Err(e),
        })
    }

    async fn handle_stalling_interval(&mut self) {
        let result = self.disconnect_if_stalling().await;
        if let Err(err) = result {
            log::warn!("Disconnecting peer failed: {err}");
        }
    }
}
