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

use crypto::random::make_pseudo_rng;
use itertools::Itertools;
use tokio::{
    sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender},
    time::MissedTickBehavior,
};

use chainstate::{
    ban_score::BanScore, chainstate_interface::ChainstateInterface, BlockIndex, BlockSource,
    Locator,
};
use common::{
    chain::{
        block::signed_block_header::SignedBlockHeader, Block, ChainConfig, GenBlock, Transaction,
    },
    primitives::{Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{
    error::{Error as MempoolError, MempoolPolicyError},
    MempoolHandle,
};
use utils::const_value::ConstValue;
use utils::sync::Arc;
use utils::{atomics::AcqRelAtomicBool, bloom_filters::rolling_bloom_filter::RollingBloomFilter};

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
    sync::types::PeerActivity,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, PeerManagerEvent, Result,
};

use super::LocalEvent;

/// Use the same parameters as Bitcoin Core (see `m_tx_inventory_known_filter`)
const KNOWN_TRANSACTIONS_ROLLING_BLOOM_FILTER_SIZE: usize = 50000;
const KNOWN_TRANSACTIONS_ROLLING_BLOOM_FPP: f64 = 0.000001;

/// Helper for `RollingBloomFilter` because `Id` does not implement `Hash`
struct TxIdWrapper(Id<Transaction>);

impl std::hash::Hash for TxIdWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

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
    peer_manager_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_rx: Receiver<SyncMessage>,
    local_event_rx: UnboundedReceiver<LocalEvent>,
    // FIXME: why not remove this atomic and ask chainstate instead? Or alternatively receive a non-atomic bool
    // during construction and with every "new tip" event?
    is_initial_block_download: Arc<AcqRelAtomicBool>,
    time_getter: TimeGetter,

    // FIXME: use "incoming_/outgoing_" prefixes to distinguish the purpose of the fields,
    // OR put them into two separate structs, e.g. IncomingDataState/OutgoingDataState.
    //
    /// A list of headers received via the `HeaderListResponse` message that we haven't yet
    /// requested the blocks for.
    known_headers: Vec<SignedBlockHeader>,
    /// A list of blocks that we requested from this peer.
    requested_blocks: BTreeSet<Id<Block>>,
    /// A queue of the blocks requested by this peer.
    blocks_queue: VecDeque<Id<Block>>,
    /// The index of the best block that we've sent to the peer.
    best_sent_block: Option<BlockIndex>,
    /// The id of the best block header that we've sent to the peer.
    best_sent_block_header: Option<Id<GenBlock>>,
    /// The id of the best block header that we've received from the peer.
    peers_best_block_that_we_have: Option<Id<GenBlock>>,
    /// A rolling filter of all known transactions (sent to us or sent by us)
    known_transactions: RollingBloomFilter<TxIdWrapper>,
    // TODO: Add a timer to remove entries.
    /// A list of transactions that have been announced by this peer. An entry is added when the
    /// identifier is announced and removed when the actual transaction or not found response is received.
    announced_transactions: BTreeSet<Id<Transaction>>,
    /// Current activity with the peer.
    peer_activity: PeerActivity,
    /// If set, send the new tip notification when the tip moves.
    /// It's set when we know that the peer knows about all of our headers.
    send_tip_updates: bool,
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
        peer_manager_sender: UnboundedSender<PeerManagerEvent>,
        sync_rx: Receiver<SyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_rx: UnboundedReceiver<LocalEvent>,
        is_initial_block_download: Arc<AcqRelAtomicBool>,
        time_getter: TimeGetter,
    ) -> Self {
        let local_services: Services = (*p2p_config.node_type).into();
        let common_services = local_services & remote_services;

        let known_transactions = RollingBloomFilter::new(
            KNOWN_TRANSACTIONS_ROLLING_BLOOM_FILTER_SIZE,
            KNOWN_TRANSACTIONS_ROLLING_BLOOM_FPP,
            &mut make_pseudo_rng(),
        );

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
            local_event_rx,
            is_initial_block_download,
            time_getter,
            known_headers: Vec::new(),
            requested_blocks: BTreeSet::new(),
            blocks_queue: VecDeque::new(),
            best_sent_block: None,
            best_sent_block_header: None,
            peers_best_block_that_we_have: None,
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
            self.request_headers().await?;
        }

        loop {
            tokio::select! {
                // FIXME: Sam: these 2 must be inside a struct/module (some kind of blackbox...)?
                message = self.sync_rx.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                block_to_send_to_peer = async {
                    self.blocks_queue.pop_front().expect("The block queue is empty")
                }, if !self.blocks_queue.is_empty() => {
                    self.send_block(block_to_send_to_peer).await?;
                }

                event = self.local_event_rx.recv() => {
                    let event = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_local_event(event).await?;
                }

                _ = stalling_interval.tick(), if self.peer_activity.earliest_expected_activity_time().is_some() => {}
            }

            // Run on each loop iteration, so it's easier to test
            if let Some(time) = self.peer_activity.earliest_expected_activity_time() {
                self.handle_stalling_interval(time).await;
            }
        }
    }

    fn send_headers(&mut self, headers: HeaderList) -> Result<()> {
        if let Some(last_header) = headers.headers().last() {
            self.best_sent_block_header = Some(last_header.block_id().into());
        }
        self.messaging_handle.send_message(self.id(), SyncMessage::HeaderList(headers))
    }

    async fn handle_new_tip(&mut self, new_tip_id: &Id<Block>) -> Result<()> {
        // This function is not supposed to be called when in IBD.
        debug_assert!(!self.is_initial_block_download.load());

        if self.send_tip_updates {
            debug_assert!(self.common_services.has_service(Service::Blocks));

            if self.best_sent_block_header.is_some() || self.peers_best_block_that_we_have.is_some()
            {
                let limit = *self.p2p_config.msg_header_count_limit;
                let new_tip_id = *new_tip_id;

                let block_ids: Vec<_> = self
                    .best_sent_block_header
                    .iter()
                    .chain(self.peers_best_block_that_we_have.iter())
                    .copied()
                    .collect();

                let headers = self
                    .chainstate_handle
                    .call(move |c| {
                        let best_block_id = c.get_best_block_id()?;
                        if best_block_id != new_tip_id {
                            // FIXME: should we ignore this event in such a case?
                            log::warn!("Got new tip event with block id {}, but the tip has changed since then to {}",
                                new_tip_id, best_block_id);
                        }

                        c.get_headers_since_latest_fork_point(&block_ids, limit)
                    })
                    .await??;

                return self.send_headers(HeaderList::new(headers));
            }
        }

        Ok(())
    }

    async fn handle_local_event(&mut self, event: LocalEvent) -> Result<()> {
        match event {
            LocalEvent::ChainstateNewTip(new_tip_id) => self.handle_new_tip(&new_tip_id).await,
            LocalEvent::MempoolNewTx(txid) => {
                if !self.known_transactions.contains(&TxIdWrapper(txid))
                    && self.common_services.has_service(Service::Transactions)
                {
                    self.add_known_transaction(txid);
                    self.messaging_handle.send_message(self.id(), SyncMessage::NewTransaction(txid))
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn request_headers(&mut self) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        if locator.len() > *self.p2p_config.msg_max_locator_count {
            // Note: msg_max_locator_count is not supposed to be configurable outside of tests,
            // so we should never get here in production code. Moreover, currently it's not
            // modified even in tests. TODO: make it a constant.
            log::warn!(
                "Sending locator of the length {}, which exceeds the maximum length {:?}",
                locator.len(),
                self.p2p_config.msg_max_locator_count
            );
        }

        log::trace!("Sending header list request to {} peer", self.id());
        self.messaging_handle.send_message(
            self.id(),
            SyncMessage::HeaderListRequest(HeaderListRequest::new(locator)),
        )?;

        self.peer_activity
            .set_expecting_headers_since(Some(self.time_getter.get_time()));

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
            // TODO: in the protocol v2 we might want to allow peers to ask for headers even if
            // the node is in IBD (e.g. based on some kind of system of permissions). ATM it's
            // not clear whether it's a good idea, so it makes sense to first check whether bitcoin
            // does something like that.

            // TODO: in the protocol v2 we should not silently ignore header requests; instead,
            // we should communicate our best block (id/height/header?) from the start, so that
            // the peer just knows that we don't have better blocks and doesn't ask us in the
            // first place.
            log::debug!("Ignoring headers request because the node is in initial block download");
            return Ok(());
        }

        // FIXME: this limit should be a constant.
        let limit = *self.p2p_config.msg_header_count_limit;
        let headers = self.chainstate_handle.call(move |c| c.get_headers(locator, limit)).await??;
        debug_assert!(headers.len() <= limit);

        // Sending a below-the-max amount of headers is a signal to the peer that we've sent
        // all headers that were available at the moment; after this, the peer may not ask us
        // for headers anymore, so we should start sending tip updates.
        self.send_tip_updates = headers.len() < limit;

        self.messaging_handle
            .send_message(self.id(), SyncMessage::HeaderList(HeaderList::new(headers)))?;

        Ok(())
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

        // A peer is allowed to ignore header requests if it's in IBD.
        // Assume this is the case if it asks us for blocks.
        self.peer_activity.set_expecting_headers_since(None);

        if self.is_initial_block_download.load() {
            // Note: currently this is not a normal situation, because a node in IBD wouldn't
            // send block headers to the peer in the first place, which means that the peer won't
            // be able to ask it for blocks.
            // FIXME: return an error with a non-zero ban score instead?
            log::warn!(
                "The node is in initial block download, but the peer {} is asking us for blocks",
                self.id()
            );
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
        let best_sent_block = self.best_sent_block.clone();
        self.chainstate_handle
            .call(move |c| {
                for id in ids {
                    let index = c.get_block_index(&id)?.ok_or(P2pError::ProtocolError(
                        ProtocolError::UnknownBlockRequested(id),
                    ))?;

                    if let Some(ref best_sent_block) = best_sent_block {
                        if index.block_height() <= best_sent_block.block_height() {
                            // This can be normal in case of reorg, check if the block id is the same.
                            let known_block_id = c
                                .get_block_id_from_height(&best_sent_block.block_height())?
                                // This should never fail because we have a block for this height.
                                // FIXME: actually, after block invalidation gets merged in, it will
                                // be possible for the mainchain to become shorter, so this "expect"
                                // may fail in the future.
                                .expect("Unable to get block id from height");
                            if &known_block_id == best_sent_block.block_id() {
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

        self.blocks_queue.extend(block_ids.into_iter());

        Ok(())
    }

    /// Delays the processing of a new block until it can be accepted by the chainstate (but not more than `max_clock_diff`).
    /// This is needed to allow the local or remote node to have slightly inaccurate clocks.
    /// Without it, even a 1 second difference can break block synchronization
    /// because one side may see the new block as invalid.
    async fn wait_for_clock_diff(&self, block_timestamp: Duration) {
        let max_block_timestamp =
            self.time_getter.get_time() + *self.chain_config.max_future_block_time_offset();
        if block_timestamp > max_block_timestamp {
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
                "Block timestamp from the future ({} seconds), peer_id: {}",
                sleep_time.as_secs(),
                self.id(),
            );
            tokio::time::sleep(sleep_time).await;
        }
    }

    async fn handle_header_list(&mut self, headers: Vec<SignedBlockHeader>) -> Result<()> {
        log::debug!("Headers list from peer {}", self.id());

        self.peer_activity.set_expecting_headers_since(None);

        if headers.is_empty() {
            // The peer can send an empty list when it has got a header request but it has no new blocks.
            return Ok(());
        }

        let last_header = headers.last().expect("Headers shouldn't be empty");
        self.wait_for_clock_diff(last_header.timestamp().as_duration_since_epoch())
            .await;

        if headers.len() > *self.p2p_config.msg_header_count_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    *self.p2p_config.msg_header_count_limit,
                ),
            ));
        }
        log::trace!("Received headers: {headers:#?}");

        // Each header must be connected to the previous one.
        if !headers
            .iter()
            .tuple_windows()
            .all(|(left, right)| &left.get_id() == right.prev_block_id())
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        // The first header must be connected to a known block (it can be in
        // the chainstate, known_headers or requested_blocks).
        let first_header_prev_id = *headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .prev_block_id();

        let first_header_is_connected_to_chainstate = self
            .chainstate_handle
            .call(move |c| c.get_gen_block_index(&first_header_prev_id))
            .await??
            .is_some();

        let first_header_is_connected_to_known_headers = if self.known_headers.is_empty() {
            false
        } else {
            // If the peer reorged, the new header list may not start where the previous one ended.
            // If so, the non-connecting old headers are now considered stale by the peer, so
            // we should remove them from known_headers.
            while let Some(known_header) = self.known_headers.last() {
                if known_header.get_id() == first_header_prev_id {
                    break;
                }

                self.known_headers.pop();
            }

            !self.known_headers.is_empty()
        };

        let first_header_is_connected_to_requested_blocks = first_header_prev_id
            .classify(&self.chain_config)
            .chain_block_id()
            .and_then(|id| self.requested_blocks.get(&id))
            .is_some();

        if !(first_header_is_connected_to_chainstate
            || first_header_is_connected_to_known_headers
            || first_header_is_connected_to_requested_blocks)
        {
            // FIXME: technically, we may have failed to send a block request on the previous
            // iteration due to some local or network issues; in that case, the corresponding
            // headers won't be present in known_headers anymore, but they
            // won't be in requested_blocks or the chainstate either.
            // Alternatively, we may have successfully received a block but then failed
            // to add it to chainstate due to a local issue, with the same result.
            // In all such cases, when the peer sends us its remaining blocks, they may appear
            // disconnected even if the peer was behaving correctly.
            // But this is a general problem of a code failure that leaves the object in an
            // intermediate state. Perhaps, when sending tip updates we should calculate the
            // fork point based on tip updates that the peer has already sent us and not on
            // what we've sent to the peer. The alternatives are:
            // 1) try to recover from this state by explicitly sending a header request to the peer.
            // 2) keep a header in known_headers until the block is received.
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        let already_downloading_blocks = if !self.requested_blocks.is_empty() {
            true
        } else if !self.known_headers.is_empty() {
            log::warn!("self.requested_blocks is empty, but self.known_headers is not");
            true
        } else {
            false
        };

        if already_downloading_blocks {
            self.known_headers.extend(headers.into_iter());
            return Ok(());
        }

        let peer_may_have_more_headers = headers.len() == *self.p2p_config.msg_header_count_limit;
        let (existing_block_headers, new_block_headers) = self
            .chainstate_handle
            .call(|c| c.split_off_leading_known_headers(headers))
            .await??;

        if let Some(last_existing_block) = existing_block_headers.last() {
            self.peers_best_block_that_we_have = Some(last_existing_block.get_id().into());
        }

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
                // This is OK because of the `headers.is_empty()` check above.
                .expect("Headers shouldn't be empty")
                .clone();
            self.chainstate_handle
                .call(|c| c.preliminary_header_check(first_header))
                .await??;
        }

        self.request_blocks(new_block_headers)
    }

    async fn handle_block_response(&mut self, block: Block) -> Result<()> {
        log::debug!("Block ({}) from peer {}", block.get_id(), self.id());

        if self.requested_blocks.take(&block.get_id()).is_none() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "block response".to_owned(),
            )));
        }

        let block = self.chainstate_handle.call(|c| c.preliminary_block_check(block)).await??;
        let block_id = block.get_id();
        let peer_id = self.id();
        self.chainstate_handle
            .call_mut(move |c| -> Result<()> {
                // If the block already exists in the block tree, skip it.
                if let Some(_) = c.get_block_index(&block.get_id())? {
                    log::debug!(
                        "Peer {} sent a block that already exists ({})",
                        peer_id,
                        block.get_id()
                    );
                } else {
                    c.process_block(block, BlockSource::Peer)?;
                }

                Ok(())
            })
            .await??;

        self.peers_best_block_that_we_have = Some(block_id.into());

        if self.requested_blocks.is_empty() {
            let headers = mem::take(&mut self.known_headers);
            // Note: we could have received some of these blocks from another peer in the meantime,
            // so filter out any existing blocks from headers first.
            // TODO: we can still request the same block from multiple peers, which is sub-optimal.
            let headers = if headers.is_empty() {
                headers
            } else {
                self.chainstate_handle
                    .call(|c| c.split_off_leading_known_headers(headers))
                    .await??
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
            // We expect additional blocks from the peer. Update the timestamp we received the
            // current one.
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
            let origin = mempool::TxOrigin::Peer(self.id());
            let _tx_status = self
                .mempool_handle
                .call_mut(move |m| m.add_transaction(transaction, origin))
                .await??;
        }

        Ok(())
    }

    fn add_known_transaction(&mut self, txid: Id<Transaction>) {
        self.known_transactions.insert(&TxIdWrapper(txid), &mut make_pseudo_rng());
    }

    // TODO: This can be optimized, see https://github.com/mintlayer/mintlayer-core/issues/829
    // for details.
    async fn handle_transaction_announcement(&mut self, tx: Id<Transaction>) -> Result<()> {
        log::debug!("Transaction announcement from {} peer: {tx}", self.id());

        self.add_known_transaction(tx);

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
        peer_manager_sender: &UnboundedSender<PeerManagerEvent>,
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
    /// The number of blocks requested equals to `P2pConfig::requested_blocks_limit`, the remaining
    /// headers are stored in the peer context.
    fn request_blocks(&mut self, mut headers: Vec<SignedBlockHeader>) -> Result<()> {
        debug_assert!(self.known_headers.is_empty());
        debug_assert!(self.requested_blocks.is_empty());

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

        self.peer_activity.set_expecting_blocks_since(Some(self.time_getter.get_time()));

        Ok(())
    }

    async fn send_block(&mut self, id: Id<Block>) -> Result<()> {
        let (block, index) = self
            .chainstate_handle
            .call(move |c| {
                // TODO: in the future, when block invalidation gets merged in and/if we implement
                // bad blocks purging, a block that once existed may not exist anymore.
                // Moreover, its block index may no longer exist (e.g. there was a suggestion
                // to delete block indices of missing blocks when resetting their failure flags).
                // P2p should handle such situations correctly.
                let index = c.get_block_index(&id);
                let block = c.get_block(id);
                (block, index)
            })
            .await?;
        // All requested blocks are already checked while processing `BlockListRequest`.
        let block = block?.unwrap_or_else(|| panic!("Unknown block requested: {id}"));
        self.best_sent_block = index?;

        log::debug!("Sending {} block to {} peer", block.get_id(), self.id());
        self.messaging_handle.send_message(
            self.id(),
            SyncMessage::BlockResponse(BlockResponse::new(block)),
        )
    }

    async fn disconnect_if_stalling(&mut self, last_activity: Duration) -> Result<()> {
        if self.time_getter.get_time() < last_activity + *self.p2p_config.sync_stalling_timeout {
            return Ok(());
        }

        // Nodes can disconnect each other if all of them are in the initial block download state,
        // but this should never occur in a normal network and can be worked around in the tests.
        let (sender, receiver) = oneshot_nofail::channel();
        log::warn!("Disconnecting peer {} for ignoring requests", self.id());
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

    async fn handle_stalling_interval(&mut self, last_activity: Duration) {
        let result = self.disconnect_if_stalling(last_activity).await;
        if let Err(err) = result {
            log::warn!("Disconnecting peer failed: {}", err);
        }
    }
}
