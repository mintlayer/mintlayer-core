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
};

use itertools::Itertools;
use tokio::{
    sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender},
    time::MissedTickBehavior,
};

use chainstate::{chainstate_interface::ChainstateInterface, BlockIndex, BlockSource, Locator};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        Block, ChainConfig, GenBlock, Transaction,
    },
    primitives::{time::Time, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::MempoolHandle;
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
    peer_manager_event::PeerDisconnectionDbAction,
    sync::{
        peer_common::{
            choose_peers_best_block, handle_message_processing_result, KnownTransactions,
        },
        types::PeerActivity,
        LocalEvent,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, PeerManagerEvent, Result,
};

use super::chainstate_handle::ChainstateHandle;

// TODO: Take into account the chain work when syncing.
/// A peer context.
///
/// Syncing logic runs in a separate task for each peer.
pub struct Peer<T: NetworkingService> {
    id: ConstValue<PeerId>,
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    peer_manager_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_msg_rx: Receiver<SyncMessage>,
    local_event_rx: UnboundedReceiver<LocalEvent>,
    time_getter: TimeGetter,
    /// Incoming data state.
    incoming: IncomingDataState,
    /// Outgoing data state.
    outgoing: OutgoingDataState,
    /// A rolling filter of all known transactions (sent to us or sent by us)
    known_transactions: KnownTransactions,
    // TODO: Add a timer to remove entries.
    /// A list of transactions that have been announced by this peer. An entry is added when the
    /// identifier is announced and removed when the actual transaction or not found response is received.
    announced_transactions: BTreeSet<Id<Transaction>>,
    /// Current activity with the peer.
    peer_activity: PeerActivity,
    /// If set, send the new tip notification when the tip moves.
    /// It's set when we know that the peer knows about all of our current mainchain headers.
    send_tip_updates: bool,
}

struct IncomingDataState {
    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    pending_headers: Vec<SignedBlockHeader>,
    /// A list of blocks that we requested from this peer.
    requested_blocks: BTreeSet<Id<Block>>,
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
    best_sent_block_header: Option<Id<GenBlock>>,
}

impl<T> Peer<T>
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
        mempool_handle: MempoolHandle,
        peer_manager_sender: UnboundedSender<PeerManagerEvent>,
        sync_msg_rx: Receiver<SyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_rx: UnboundedReceiver<LocalEvent>,
        time_getter: TimeGetter,
    ) -> Self {
        let known_transactions = KnownTransactions::new();

        Self {
            id: id.into(),
            chain_config,
            p2p_config,
            common_services,
            chainstate_handle,
            mempool_handle,
            peer_manager_sender,
            messaging_handle,
            sync_msg_rx,
            local_event_rx,
            time_getter,
            incoming: IncomingDataState {
                pending_headers: Vec::new(),
                requested_blocks: BTreeSet::new(),
                peers_best_block_that_we_have: None,
            },
            outgoing: OutgoingDataState {
                blocks_queue: VecDeque::new(),
                best_sent_block: None,
                best_sent_block_header: None,
            },
            known_transactions,
            announced_transactions: BTreeSet::new(),
            peer_activity: PeerActivity::new(),
            send_tip_updates: false,
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
            log::debug!("[peer id = {}] Asking for headers initially", self.id());
            self.request_headers().await?;
        }

        loop {
            tokio::select! {
                message = self.sync_msg_rx.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                block_to_send_to_peer = async {
                    self.outgoing.blocks_queue.pop_front().expect("The block queue is empty")
                }, if !self.outgoing.blocks_queue.is_empty() => {
                    self.send_block(block_to_send_to_peer).await?;
                }

                event = self.local_event_rx.recv() => {
                    let event = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_local_event(event).await?;
                }

                _ = stalling_interval.tick(), if self.peer_activity.earliest_expected_activity_time().is_some() => {}
            }

            // Run on each loop iteration, so it's easier to test
            self.handle_stalling_interval().await;
        }
    }

    fn send_message(&mut self, message: SyncMessage) -> Result<()> {
        self.messaging_handle.send_message(self.id(), message)
    }

    fn send_headers(&mut self, headers: HeaderList) -> Result<()> {
        if let Some(last_header) = headers.headers().last() {
            self.outgoing.best_sent_block_header = Some(last_header.block_id().into());
        }
        self.send_message(SyncMessage::HeaderList(headers))
    }

    async fn handle_new_tip(&mut self, new_tip_id: &Id<Block>) -> Result<()> {
        // This function is not supposed to be called when in IBD.
        debug_assert!(!self.chainstate_handle.is_initial_block_download().await?);

        let best_sent_block_id =
            self.outgoing.best_sent_block.as_ref().map(|index| (*index.block_id()).into());

        log::debug!(
            concat!(
                "[peer id = {}] In handle_new_tip: send_tip_updates = {}, ",
                "best_sent_block_header = {:?}, best_sent_block = {:?}, ",
                "peers_best_block_that_we_have = {:?}"
            ),
            self.id(),
            self.send_tip_updates,
            self.outgoing.best_sent_block_header,
            best_sent_block_id,
            self.incoming.peers_best_block_that_we_have
        );

        if self.send_tip_updates {
            debug_assert!(self.common_services.has_service(Service::Blocks));

            if self.incoming.peers_best_block_that_we_have.is_some()
                || best_sent_block_id.is_some()
                || self.outgoing.best_sent_block_header.is_some()
            {
                let limit = *self.p2p_config.msg_header_count_limit;
                let new_tip_id = *new_tip_id;

                let block_ids: Vec<_> = self
                    .incoming
                    .peers_best_block_that_we_have
                    .iter()
                    .chain(best_sent_block_id.iter())
                    .chain(self.outgoing.best_sent_block_header.iter())
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
                    log::warn!(
                        concat!(
                            "[peer id = {}] Got new tip event with block id {}, ",
                            "but there is nothing to send"
                        ),
                        self.id(),
                        new_tip_id,
                    );
                } else if best_block_id != new_tip_id {
                    // If we got here, another "new tip" event should be generated soon,
                    // so we may ignore this one (and it makes sense to ignore it to avoid sending
                    // the same header list multiple times).
                    // Note: once we take best_sent_block_header into account when sending headers,
                    // this special handling won't be needed, because we'll never send the same
                    // header list twice in that case.
                    log::warn!(
                        concat!(
                            "[peer id = {}] Got new tip event with block id {}, ",
                            "but the tip has changed since then to {}"
                        ),
                        self.id(),
                        new_tip_id,
                        best_block_id
                    );
                } else {
                    log::debug!(
                        "[peer id = {}] Sending header list of length {}",
                        self.id(),
                        headers.len()
                    );
                    return self.send_headers(HeaderList::new(headers));
                }
            } else {
                // Note: if we got here, then we haven't received a single header request or
                // response from the peer yet (otherwise peers_best_block_that_we_have would be
                // set at least to the genesis). There is no point in doing anything specific here.
                log::warn!(
                    "[peer id = {}] Ignoring new tip event, because we don't know what to send",
                    self.id()
                );
            }
        }

        Ok(())
    }

    async fn handle_local_event(&mut self, event: LocalEvent) -> Result<()> {
        log::debug!(
            "[peer id = {}] Handling local peer mgr event: {event:?}",
            self.id()
        );

        match event {
            LocalEvent::ChainstateNewTip(new_tip_id) => self.handle_new_tip(&new_tip_id).await,
            LocalEvent::MempoolNewTx(txid) => {
                if !self.known_transactions.contains(&txid)
                    && self.common_services.has_service(Service::Transactions)
                {
                    self.add_known_transaction(txid);
                    self.send_message(SyncMessage::NewTransaction(txid))
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn request_headers(&mut self) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| Ok(this.get_locator()?)).await?;
        if locator.len() > *self.p2p_config.msg_max_locator_count {
            // Note: msg_max_locator_count is not supposed to be configurable outside of tests,
            // so we should never get here in production code. Moreover, currently it's not
            // modified even in tests. TODO: make it a constant.
            log::warn!(
                "[peer id = {}] Sending locator of the length {}, which exceeds the maximum length {:?}",
                self.id(),
                locator.len(),
                self.p2p_config.msg_max_locator_count
            );
        }

        log::debug!("[peer id = {}] Sending header list request", self.id());
        self.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))?;

        self.peer_activity
            .set_expecting_headers_since(Some(self.time_getter.get_time()));

        Ok(())
    }

    async fn handle_message(&mut self, message: SyncMessage) -> Result<()> {
        log::trace!(
            "[peer id = {}] Handling message from the peer: {message:?}",
            self.id()
        );

        let res = match message {
            SyncMessage::HeaderListRequest(r) => self.handle_header_request(r.into_locator()).await,
            SyncMessage::BlockListRequest(r) => self.handle_block_request(r.into_block_ids()).await,
            SyncMessage::HeaderList(l) => self.handle_header_list(l.into_headers()).await,
            SyncMessage::BlockResponse(r) => self.handle_block_response(r.into_block()).await,
            SyncMessage::NewTransaction(id) => self.handle_transaction_announcement(id).await,
            SyncMessage::TransactionRequest(id) => self.handle_transaction_request(id).await,
            SyncMessage::TransactionResponse(tx) => self.handle_transaction_response(tx).await,
        };
        handle_message_processing_result(&self.peer_manager_sender, self.id(), res).await
    }

    /// Processes a header request by sending requested data to the peer.
    async fn handle_header_request(&mut self, locator: Locator) -> Result<()> {
        log::debug!("[peer id = {}] Handling header request", self.id());

        if locator.len() > *self.p2p_config.msg_max_locator_count {
            return Err(P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(
                locator.len(),
                *self.p2p_config.msg_max_locator_count,
            )));
        }

        if self.chainstate_handle.is_initial_block_download().await? {
            // TODO: in the protocol v2 we might want to allow peers to ask for headers even if
            // the node is in IBD (e.g. based on some kind of system of permissions). ATM it's
            // not clear whether it's a good idea, so it makes sense to first check whether bitcoin
            // does something like that.
            // TODO: in the protocol v2 we should not silently ignore header requests; instead,
            // we should communicate our best block (id/height/header?) from the start, so that
            // the peer just knows that we don't have better blocks and doesn't ask us in the
            // first place.
            // See the issue #1110.
            log::debug!("[peer id = {}] Ignoring headers request because the node is in initial block download", self.id());
            return Ok(());
        }

        // Obtain headers and also determine the new value for peers_best_block_that_we_have.
        let header_count_limit = *self.p2p_config.msg_header_count_limit;
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
        // all headers that were available at the moment; after this, the peer may not ask us
        // for headers anymore, so we should start sending tip updates.
        self.send_tip_updates = headers.len() < header_count_limit;

        self.send_headers(HeaderList::new(headers))
    }

    /// Processes the blocks request.
    async fn handle_block_request(&mut self, block_ids: Vec<Id<Block>>) -> Result<()> {
        utils::ensure!(
            !block_ids.is_empty(),
            P2pError::ProtocolError(ProtocolError::ZeroBlocksInRequest)
        );

        log::debug!(
            "[peer id = {}] Handling block request: {}-{} ({})",
            self.id(),
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );

        // A peer is allowed to ignore header requests if it's in IBD.
        // Assume this is the case if it asks us for blocks.
        self.peer_activity.set_expecting_headers_since(None);

        if self.chainstate_handle.is_initial_block_download().await? {
            // Note: currently this is not a normal situation, because a node in IBD wouldn't
            // send block headers to the peer in the first place, which means that the peer won't
            // be able to ask it for blocks.
            // TODO: return an error with a non-zero ban score instead?
            log::warn!(
                "[peer id = {}] The node is in initial block download, but the peer is asking us for blocks",
                self.id()
            );
            return Ok(());
        }

        // Check that a peer doesn't exceed the blocks limit.
        self.p2p_config
            .max_request_blocks_count
            .checked_sub(block_ids.len())
            .and_then(|n| n.checked_sub(self.outgoing.blocks_queue.len()))
            .ok_or(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(
                    block_ids.len() + self.outgoing.blocks_queue.len(),
                    *self.p2p_config.max_request_blocks_count,
                ),
            ))?;

        // Check that all the blocks are known and haven't been already requested.
        let ids = block_ids.clone();
        let best_sent_block = self.outgoing.best_sent_block.clone();
        self.chainstate_handle
            .call(move |c| {
                for id in ids {
                    // TODO: As it is mentioned in send_block, in the future it may be possible
                    // for previously existing blocks and block indices to get removed due to
                    // invalidation. P2p will need to handle this situation correctly. See issue
                    // #1033 for more details.
                    let index = c.get_block_index(&id)?.ok_or(P2pError::ProtocolError(
                        ProtocolError::UnknownBlockRequested(id),
                    ))?;

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
    async fn wait_for_clock_diff(&self, block_timestamp: BlockTimestamp) {
        let max_accepted_time = (self.time_getter.get_time()
            + *self.chain_config.max_future_block_time_offset())
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

            let sleep_time = std::cmp::min(clock_diff, *self.p2p_config.max_clock_diff);
            log::debug!(
                "[peer id = {}] Block timestamp from the future ({} seconds)",
                self.id(),
                sleep_time.as_secs()
            );
            tokio::time::sleep(sleep_time).await;
        }
    }

    async fn handle_header_list(&mut self, headers: Vec<SignedBlockHeader>) -> Result<()> {
        log::debug!("[peer id = {}] Handling header list", self.id());

        self.peer_activity.set_expecting_headers_since(None);

        if headers.is_empty() {
            // The peer can send an empty list when it has got a header request but it has no new blocks.
            return Ok(());
        }

        let last_header = headers.last().expect("Headers shouldn't be empty");
        self.wait_for_clock_diff(last_header.timestamp()).await;

        if headers.len() > *self.p2p_config.msg_header_count_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    *self.p2p_config.msg_header_count_limit,
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

        // The first header must be connected to a known block (it can be in
        // the chainstate, pending_headers or requested_blocks).
        let first_header_prev_id = *headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .prev_block_id();

        let first_header_is_connected_to_chainstate = self
            .chainstate_handle
            .call(move |c| Ok(c.get_gen_block_index(&first_header_prev_id)?))
            .await?
            .is_some();

        let first_header_is_connected_to_pending_headers = {
            // If the peer reorged, the new header list may not start where the previous one ended.
            // If so, the non-connecting old headers are now considered stale by the peer, so
            // we should remove them from pending_headers.
            while let Some(known_header) = self.incoming.pending_headers.last() {
                if known_header.get_id() == first_header_prev_id {
                    break;
                }

                self.incoming.pending_headers.pop();
            }

            !self.incoming.pending_headers.is_empty()
        };

        let first_header_is_connected_to_requested_blocks = first_header_prev_id
            .classify(&self.chain_config)
            .chain_block_id()
            .and_then(|id| self.incoming.requested_blocks.get(&id))
            .is_some();

        if !(first_header_is_connected_to_chainstate
            || first_header_is_connected_to_pending_headers
            || first_header_is_connected_to_requested_blocks)
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        let already_downloading_blocks = if !self.incoming.requested_blocks.is_empty() {
            true
        } else if !self.incoming.pending_headers.is_empty() {
            log::debug!(
                concat!(
                    "[peer id = {}] self.incoming.requested_blocks is empty, ",
                    "but self.incoming.pending_headers is not"
                ),
                self.id()
            );
            true
        } else {
            false
        };

        if already_downloading_blocks {
            self.incoming.pending_headers.extend(headers.into_iter());
            return Ok(());
        }

        let peer_may_have_more_headers = headers.len() == *self.p2p_config.msg_header_count_limit;

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

        if new_block_headers.is_empty() {
            if peer_may_have_more_headers {
                self.request_headers().await?;
            }
            return Ok(());
        }

        // Now use preliminary_header_check; this can only be done for the first header,
        // which is now known to be connected to the chainstate.
        // Note: if the first header in the original "headers" vector was connected, the first
        // header in "new_block_headers" will be connected as well.
        debug_assert!(first_header_is_connected_to_chainstate);
        if first_header_is_connected_to_chainstate {
            let first_header = new_block_headers
                .first()
                // This is OK because of the `new_block_headers.is_empty()` check above.
                .expect("Headers shouldn't be empty")
                .clone();
            self.chainstate_handle
                .call(|c| Ok(c.preliminary_header_check(first_header)?))
                .await?;
        }

        self.request_blocks(new_block_headers)
    }

    async fn handle_block_response(&mut self, block: Block) -> Result<()> {
        let block_id = block.get_id();
        log::debug!(
            "[peer id = {}] Handling block response, block id = {}",
            self.id(),
            block_id
        );

        // Clear the block expectation time, because we've received a block.
        // The code below will set it again if needed.
        self.peer_activity.set_expecting_blocks_since(None);

        if self.incoming.requested_blocks.take(&block.get_id()).is_none() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "block response".to_owned(),
            )));
        }

        let block = self.chainstate_handle.call(|c| Ok(c.preliminary_block_check(block)?)).await?;

        // Process the block and also determine the new value for peers_best_block_that_we_have.
        let peer_id = self.id();
        let old_peers_best_block_that_we_have = self.incoming.peers_best_block_that_we_have;
        let (best_block, new_tip_received) = self
            .chainstate_handle
            .call_mut(move |c| {
                // If the block already exists in the block tree, skip it.
                let new_tip_received = if c.get_block_index(&block.get_id())?.is_some() {
                    log::debug!(
                        "[peer id = {}] The peer sent a block that already exists ({})",
                        peer_id,
                        block_id
                    );
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
            self.peer_manager_sender.send(PeerManagerEvent::NewTipReceived {
                peer_id: self.id(),
                block_id,
            })?;
        }

        if self.incoming.requested_blocks.is_empty() {
            let headers = mem::take(&mut self.incoming.pending_headers);
            // Note: we could have received some of these blocks from another peer in the meantime,
            // so filter out any existing blocks from 'headers' first.
            // TODO: we can still request the same block from multiple peers, which is sub-optimal.
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
        } else {
            // We expect additional blocks from the peer, update the timestamp.
            self.peer_activity.set_expecting_blocks_since(Some(self.time_getter.get_time()));
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

        self.send_message(SyncMessage::TransactionResponse(res))?;

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
            let origin = mempool::tx_origin::RemoteTxOrigin::new(self.id());
            let txid = transaction.transaction().get_id();
            let tx_status = self
                .mempool_handle
                .call_mut(move |m| m.add_transaction_remote(transaction, origin))
                .await??;
            match tx_status {
                mempool::TxStatus::InMempool => {
                    self.peer_manager_sender.send(
                        PeerManagerEvent::NewValidTransactionReceived {
                            peer_id: self.id(),
                            txid,
                        },
                    )?;
                }
                mempool::TxStatus::InOrphanPool => {}
            }
        }

        Ok(())
    }

    fn add_known_transaction(&mut self, txid: Id<Transaction>) {
        self.known_transactions.insert(&txid);
    }

    // TODO: This can be optimized, see https://github.com/mintlayer/mintlayer-core/issues/829
    // for details.
    async fn handle_transaction_announcement(&mut self, tx: Id<Transaction>) -> Result<()> {
        log::debug!(
            "[peer id = {}] Handling transaction announcement: {tx}",
            self.id()
        );

        self.add_known_transaction(tx);

        if self.chainstate_handle.is_initial_block_download().await? {
            log::debug!(
                "[peer id = {}] Ignoring transaction announcement because the node is in initial block download", self.id()
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
            self.send_message(SyncMessage::TransactionRequest(tx))?;
            assert!(self.announced_transactions.insert(tx));
        }

        Ok(())
    }

    /// Sends a block list request.
    ///
    /// The number of blocks requested equals `P2pConfig::requested_blocks_limit`, the remaining
    /// headers are stored in the peer context.
    fn request_blocks(&mut self, mut headers: Vec<SignedBlockHeader>) -> Result<()> {
        debug_assert!(self.incoming.pending_headers.is_empty());
        debug_assert!(self.incoming.requested_blocks.is_empty());

        // Remove already requested blocks.
        headers.retain(|h| !self.incoming.requested_blocks.contains(&h.get_id()));
        if headers.is_empty() {
            return Ok(());
        }

        if headers.len() > *self.p2p_config.max_request_blocks_count {
            self.incoming.pending_headers =
                headers.split_off(*self.p2p_config.max_request_blocks_count);
        }

        let block_ids: Vec<_> = headers.into_iter().map(|h| h.get_id()).collect();
        log::debug!(
            "[peer id = {}] Requesting blocks from the peer: {}-{} ({})",
            self.id(),
            block_ids.first().expect("block_ids is not empty"),
            block_ids.last().expect("block_ids is not empty"),
            block_ids.len(),
        );
        self.send_message(SyncMessage::BlockListRequest(BlockListRequest::new(
            block_ids.clone(),
        )))?;
        self.incoming.requested_blocks.extend(block_ids);

        self.peer_activity.set_expecting_blocks_since(Some(self.time_getter.get_time()));

        Ok(())
    }

    async fn send_block(&mut self, id: Id<Block>) -> Result<()> {
        let (block, index) = self
            .chainstate_handle
            .call(move |c| {
                let index = c.get_block_index(&id);
                let block = c.get_block(id);
                Ok((block, index))
            })
            .await?;
        // All requested blocks are already checked while processing `BlockListRequest`.
        // TODO: in the future, when block invalidation gets merged in and/if we implement
        // bad blocks purging, a block that once existed may not exist anymore.
        // Moreover, its block index may no longer exist (e.g. there was a suggestion
        // to delete block indices of missing blocks when resetting their failure flags).
        // P2p should handle such situations correctly (see issue #1033 for more details).
        let block = block?.unwrap_or_else(|| panic!("Unknown block requested: {id}"));
        self.outgoing.best_sent_block = index?;

        log::debug!(
            "[peer id = {}] Sending block with id = {} to the peer",
            self.id(),
            block.get_id()
        );
        self.send_message(SyncMessage::BlockResponse(BlockResponse::new(block)))
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
        log::warn!("[peer id = {}] Disconnecting the peer for ignoring requests, headers_req_stalling = {}, blocks_req_stalling = {}",
            self.id(), headers_req_stalling, blocks_req_stalling);
        self.peer_manager_sender.send(PeerManagerEvent::Disconnect(
            self.id(),
            PeerDisconnectionDbAction::Keep,
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
            log::warn!(
                "[peer id = {}] Disconnecting peer failed: {}",
                self.id(),
                err
            );
        }
    }
}
