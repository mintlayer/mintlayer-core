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

//! This module is responsible for both initial syncing and further blocks processing (the reaction
//! to block announcement from peers and the announcement of blocks produced by this node).

mod chainstate_handle;
mod peer;
mod peer_activity;
mod peer_common;
pub mod sync_status;

use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};

use dyn_clone::DynClone;
use futures::never::Never;
use networking::types::ConnectionDirection;
use randomness::{make_pseudo_rng, RngExt as _};
use tokio::{
    sync::mpsc::{self, Receiver, UnboundedReceiver, UnboundedSender},
    task::JoinSet,
    time::MissedTickBehavior,
};
use tracing::Instrument;

use common::{
    chain::{config::ChainConfig, GenBlock, Transaction},
    primitives::Id,
    time_getter::{MonotonicTimeGetter, TimeGetter},
};
use logging::log;
use mempool::{
    event::{MempoolEvent, TransactionProcessedEvent},
    tx_origin::TxOrigin,
    MempoolHandle,
};
use utils::{
    debug_panic_or_log, sender_with_id::MpscUnboundedSenderWithId, sync::Arc, tap_log::TapLog,
    tokio_spawn_in_join_set,
};

use crate::{
    config::P2pConfig,
    error::P2pError,
    message::{BlockSyncMessage, TransactionSyncMessage},
    net::{
        types::{services::Services, SyncingEvent},
        MessagingService, NetworkingService, SyncingEventReceiver,
    },
    protocol::SupportedProtocolVersion,
    sync::peer::{
        block_manager::PeerBlockSyncManagerLocalEvent,
        transaction_manager::{
            PeerTransactionSyncManagerLocalEvent, PeerTransactionSyncManagerLocalNotification,
        },
    },
    types::peer_id::PeerId,
    PeerManagerEvent, Result,
};

use self::chainstate_handle::ChainstateHandle;

// 1 to 1.5 average distances between blocks.
pub const UNCONFIRMED_TX_REQUEUE_MIN_DELAY: Duration = Duration::from_secs(120);
pub const UNCONFIRMED_TX_REQUEUE_MAX_DELAY: Duration = Duration::from_secs(180);

pub struct PeerContext {
    tasks: JoinSet<()>,
    block_mgr_event_sender: UnboundedSender<PeerBlockSyncManagerLocalEvent>,
    tx_mgr_event_sender: UnboundedSender<PeerTransactionSyncManagerLocalEvent>,
}

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
pub struct SyncManager<T: NetworkingService> {
    /// The chain configuration.
    chain_config: Arc<ChainConfig>,

    /// The p2p configuration.
    p2p_config: Arc<P2pConfig>,

    messaging_handle: T::MessagingHandle,
    syncing_event_receiver: T::SyncingEventReceiver,

    /// A sender for the peer manager events.
    peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,

    tx_mgr_notification_sender:
        UnboundedSender<(PeerId, PeerTransactionSyncManagerLocalNotification)>,
    tx_mgr_notification_receiver:
        UnboundedReceiver<(PeerId, PeerTransactionSyncManagerLocalNotification)>,

    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,

    /// The list of connected peers
    peers: HashMap<PeerId, PeerContext>,

    /// Transactions with local origin that were forwarded to peer tasks to be announced to the peers
    /// and for which the actual sending has not been confirmed yet.
    unconfirmed_local_transactions: BTreeSet<Id<Transaction>>,

    // TODO: most (or maybe all) places in the sync mgr where `time_getter` is currently used
    // should probably use `monotonic_time_getter` instead (because we're dealing with delays here
    // and don't need absolute time).
    time_getter: TimeGetter,
    monotonic_time_getter: MonotonicTimeGetter,

    /// SyncManager's observer for use by tests.
    observer: Option<BoxedObserver>,
}

/// Syncing manager
impl<T> SyncManager<T>
where
    T: NetworkingService + 'static,
    T::MessagingHandle: MessagingService,
    T::SyncingEventReceiver: SyncingEventReceiver,
{
    /// Creates a new sync manager instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        messaging_handle: T::MessagingHandle,
        syncing_event_receiver: T::SyncingEventReceiver,
        chainstate_handle: chainstate::ChainstateHandle,
        mempool_handle: MempoolHandle,
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        time_getter: TimeGetter,
        monotonic_time_getter: MonotonicTimeGetter,
    ) -> Self {
        Self::new_generic(
            chain_config,
            p2p_config,
            messaging_handle,
            syncing_event_receiver,
            chainstate_handle,
            mempool_handle,
            peer_mgr_event_sender,
            time_getter,
            monotonic_time_getter,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_generic(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        messaging_handle: T::MessagingHandle,
        syncing_event_receiver: T::SyncingEventReceiver,
        chainstate_handle: chainstate::ChainstateHandle,
        mempool_handle: MempoolHandle,
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        time_getter: TimeGetter,
        monotonic_time_getter: MonotonicTimeGetter,
        observer: Option<BoxedObserver>,
    ) -> Self {
        let (tx_mgr_notification_sender, tx_mgr_notification_receiver) = mpsc::unbounded_channel();

        Self {
            chain_config,
            p2p_config,
            messaging_handle,
            syncing_event_receiver,
            peer_mgr_event_sender,
            tx_mgr_notification_sender,
            tx_mgr_notification_receiver,
            chainstate_handle: ChainstateHandle::new(chainstate_handle),
            mempool_handle,
            peers: Default::default(),
            unconfirmed_local_transactions: BTreeSet::new(),
            time_getter,
            monotonic_time_getter,
            observer,
        }
    }

    /// Runs the sync manager event loop.
    pub async fn run(mut self) -> Result<Never> {
        log::info!("Starting SyncManager");

        let maintenance_interval_duration = Duration::from_secs(1);
        let mut maintenance_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + maintenance_interval_duration,
            maintenance_interval_duration,
        );
        maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut new_tip_receiver = subscribe_to_new_tip(&self.chainstate_handle).await?;
        let mut tx_processed_receiver = subscribe_to_tx_processed(&self.mempool_handle).await?;

        let mut next_time_to_requeue_unconfirmed_local_txs = self.monotonic_time_getter.get_time();

        loop {
            tokio::select! {
                block_id = new_tip_receiver.recv() => {
                    // This error can only occur when chainstate drops an events subscriber.
                    let block_id = block_id.expect("New tip sender was closed");
                    self.handle_new_tip(block_id).await?;
                },

                tx_proc = tx_processed_receiver.recv() => {
                    let tx_proc = tx_proc.expect("Transaction processed sender closed");
                    self.handle_transaction_processed(&tx_proc)?;
                },

                event = self.syncing_event_receiver.poll_next() => {
                    self.handle_peer_event(event?).await;
                },

                notif_with_id = self.tx_mgr_notification_receiver.recv() => {
                    if let Some((peer_id, notif)) = notif_with_id {
                        self.handle_tx_mgr_notification(peer_id, notif);
                    }
                }

                _ = maintenance_interval.tick() => {}
            }

            let now = self.monotonic_time_getter.get_time();

            if now >= next_time_to_requeue_unconfirmed_local_txs {
                self.requeue_unconfirmed_local_transactions().await?;

                let delay = make_pseudo_rng().random_range(
                    UNCONFIRMED_TX_REQUEUE_MIN_DELAY..UNCONFIRMED_TX_REQUEUE_MAX_DELAY,
                );

                next_time_to_requeue_unconfirmed_local_txs = now + delay;
            }
        }
    }

    async fn requeue_unconfirmed_local_transactions(&mut self) -> Result<()> {
        if !self.unconfirmed_local_transactions.is_empty() {
            // Filter out transactions that are no longer in the mempool.
            // Note that PeerTransactionSyncManager will check this too, but we have to do
            // it here as well, to make sure that txs that were removed from the mempool (e.g.
            // due to having been mined) don't remain in `unconfirmed_local_transactions` forever.
            let tx_ids = std::mem::take(&mut self.unconfirmed_local_transactions);
            self.unconfirmed_local_transactions = self
                .mempool_handle
                .call(move |m| {
                    let mut tx_ids = tx_ids;
                    tx_ids.retain(|tx_id| m.transaction(tx_id).is_some());
                    tx_ids
                })
                .await?;
        }

        if !self.unconfirmed_local_transactions.is_empty() {
            let txs = Arc::new(self.unconfirmed_local_transactions.clone());
            self.send_tx_mgr_event(
                &PeerTransactionSyncManagerLocalEvent::UnconfirmedLocalTxsReannouncement(txs),
            );
        }

        Ok(())
    }

    /// Starts a task for the new peer.
    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        common_services: Services,
        direction: ConnectionDirection,
        _protocol_version: SupportedProtocolVersion,
        block_sync_msg_receiver: Receiver<BlockSyncMessage>,
        transaction_sync_msg_receiver: Receiver<TransactionSyncMessage>,
    ) {
        log::debug!("Registering peer {peer_id} to sync manager");

        let mut peer_tasks = JoinSet::new();

        let (block_mgr_event_sender, block_mgr_event_receiver) = mpsc::unbounded_channel();
        let mut mgr = peer::block_manager::PeerBlockSyncManager::<T>::new(
            peer_id,
            common_services,
            Arc::clone(&self.chain_config),
            Arc::clone(&self.p2p_config),
            self.chainstate_handle.clone(),
            self.peer_mgr_event_sender.clone(),
            block_sync_msg_receiver,
            self.messaging_handle.clone(),
            block_mgr_event_receiver,
            self.time_getter.clone(),
        );

        tokio_spawn_in_join_set(
            &mut peer_tasks,
            async move {
                mgr.run().await;
            }
            .in_current_span(),
            &format!("Peer[id={peer_id}] block sync mgr"),
        );

        let (tx_mgr_event_sender, tx_mgr_event_receiver) = mpsc::unbounded_channel();
        let mut mgr = peer::transaction_manager::PeerTransactionSyncManager::<T>::new(
            peer_id,
            common_services,
            direction,
            Arc::clone(&self.p2p_config),
            self.chainstate_handle.clone(),
            self.mempool_handle.clone(),
            self.peer_mgr_event_sender.clone(),
            transaction_sync_msg_receiver,
            self.messaging_handle.clone(),
            tx_mgr_event_receiver,
            MpscUnboundedSenderWithId::new(peer_id, self.tx_mgr_notification_sender.clone()),
            self.time_getter.clone(),
            self.monotonic_time_getter.clone(),
            self.observer.clone(),
        );

        tokio_spawn_in_join_set(
            &mut peer_tasks,
            async move {
                mgr.run().await;
            }
            .in_current_span(),
            &format!("Peer[id={peer_id}] tx sync mgr"),
        );

        let peer_context = PeerContext {
            tasks: peer_tasks,
            block_mgr_event_sender,
            tx_mgr_event_sender,
        };

        let prev_task = self.peers.insert(peer_id, peer_context);
        assert!(prev_task.is_none(), "Registered duplicated peer: {peer_id}");
    }

    /// Stops the task of the given peer by closing the corresponding channel.
    fn unregister_peer(&mut self, peer_id: PeerId) {
        log::debug!("Unregister peer {peer_id} from sync manager");
        let mut peer = self
            .peers
            .remove(&peer_id)
            .unwrap_or_else(|| panic!("Unregistering unknown peer: {peer_id}"));
        // Call `abort` because the peer tasks may be sleeping for a long time in the `sync_clock` function
        peer.tasks.abort_all();
    }

    fn send_block_mgr_event(&mut self, event: &PeerBlockSyncManagerLocalEvent) {
        for peer_ctx in self.peers.values_mut() {
            let _ = peer_ctx.block_mgr_event_sender.send(event.clone());
        }
    }

    fn send_tx_mgr_event(&mut self, event: &PeerTransactionSyncManagerLocalEvent) {
        for peer_ctx in self.peers.values_mut() {
            let _ = peer_ctx.tx_mgr_event_sender.send(event.clone());
        }
    }

    /// Announces the header of a new block to peers.
    async fn handle_new_tip(&mut self, block_id: Id<GenBlock>) -> Result<()> {
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::NewChainstateTip(block_id))
            .map_err(|_| P2pError::ChannelClosed)?;

        if self.chainstate_handle.is_initial_block_download().await? {
            return Ok(());
        }

        log::debug!("Broadcasting a new tip {}", block_id);
        self.send_block_mgr_event(&PeerBlockSyncManagerLocalEvent::ChainstateNewTip(block_id));

        Ok(())
    }

    fn handle_transaction_processed(
        &mut self,
        tx_proc_event: &TransactionProcessedEvent,
    ) -> Result<()> {
        let tx_id = *tx_proc_event.tx_id();
        let origin = tx_proc_event.origin();

        match tx_proc_event.result() {
            Ok(duplicate_status) => {
                use mempool::{tx_options::TxRelayPolicy, TransactionDuplicateStatus};
                match tx_proc_event.relay_policy() {
                    TxRelayPolicy::DoRelay => {
                        let (need_relay, status_str) = match duplicate_status {
                            TransactionDuplicateStatus::New => (true, "new"),

                            TransactionDuplicateStatus::Duplicate => {
                                let need_relay = match tx_proc_event.origin() {
                                    TxOrigin::Local(_) => true,
                                    TxOrigin::Remote(_) => {
                                        // The mempool is supposed to only send TransactionProcessedEvent's for duplicate
                                        // transactions if they have the local origin.
                                        debug_panic_or_log!(
                                            "Unexpected TransactionProcessedEvent with non-local duplicate transaction received from mempool"
                                        );
                                        false
                                    }
                                };
                                (need_relay, "duplicate")
                            }
                        };

                        if need_relay {
                            log::info!(
                                "Propagating {status_str} transaction {tx_id} originating in {origin}"
                            );

                            self.send_tx_mgr_event(
                                &PeerTransactionSyncManagerLocalEvent::MempoolRelayableTx(tx_id),
                            );

                            match tx_proc_event.origin() {
                                TxOrigin::Local(_) => {
                                    self.unconfirmed_local_transactions.insert(tx_id);
                                }
                                TxOrigin::Remote(_) => {}
                            }
                        } else {
                            log::trace!(
                                "Not propagating {status_str} transaction {tx_id} originating in {origin}"
                            );
                        }
                    }
                    TxRelayPolicy::DontRelay => {
                        log::trace!("Not propagating transaction {tx_id} originating in {origin}");
                    }
                }
            }
            Err(err) => match origin {
                TxOrigin::Remote(remote_origin) => {
                    // Punish the original peer for submitting an invalid transaction according
                    // to mempool ban score.
                    let ban_score = tx_proc_event.ban_score();
                    if ban_score > 0 {
                        let (response_sender, _response_receiver) =
                            crate::utils::oneshot_nofail::channel();
                        let peer_id = remote_origin.peer_id();

                        log::debug!(
                            concat!(
                                "Transaction {:x} originating from peer {} is invalid ",
                                "with ban score of {}, sending AdjustPeerScore event (error = {})"
                            ),
                            tx_id,
                            peer_id,
                            ban_score,
                            err
                        );

                        let event = PeerManagerEvent::AdjustPeerScore {
                            peer_id,
                            adjust_by: ban_score,
                            reason: err.to_string(),
                            response_sender,
                        };
                        self.peer_mgr_event_sender
                            .send(event)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                }
                TxOrigin::Local(_) => (),
            },
        }
        Ok(())
    }

    /// Sends an event to the corresponding peer.
    async fn handle_peer_event(&mut self, event: SyncingEvent) {
        match event {
            SyncingEvent::Connected {
                peer_id,
                common_services,
                direction,
                protocol_version,
                block_sync_msg_receiver,
                transaction_sync_msg_receiver,
            } => self.register_peer(
                peer_id,
                common_services,
                direction,
                protocol_version,
                block_sync_msg_receiver,
                transaction_sync_msg_receiver,
            ),
            SyncingEvent::Disconnected { peer_id } => {
                Self::notify_mempool_peer_disconnected(&self.mempool_handle, peer_id).await;
                self.unregister_peer(peer_id);
            }
        }
    }

    fn handle_tx_mgr_notification(
        &mut self,
        _peer_id: PeerId,
        notif: PeerTransactionSyncManagerLocalNotification,
    ) {
        match notif {
            PeerTransactionSyncManagerLocalNotification::TransactionSent(id) => {
                self.unconfirmed_local_transactions.remove(&id);
            }
        }
    }

    async fn notify_mempool_peer_disconnected(mempool_handle: &MempoolHandle, peer_id: PeerId) {
        mempool_handle
            .call_mut(move |mempool| mempool.notify_peer_disconnected(peer_id))
            .await
            .unwrap_or_else(|err| {
                log::error!("Mempool dead upon peer {peer_id} disconnect: {err}");
            })
    }

    pub fn chainstate(&self) -> &ChainstateHandle {
        &self.chainstate_handle
    }
}

/// Returns a receiver for the chainstate `NewTip` events.
pub async fn subscribe_to_new_tip(
    chainstate_handle: &ChainstateHandle,
) -> Result<UnboundedReceiver<Id<GenBlock>>> {
    let (sender, receiver) = mpsc::unbounded_channel();

    let subscribe_func =
        Arc::new(
            move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                chainstate::ChainstateEvent::NewTip {
                    id: block_id,
                    height: _,
                    is_initial_block_download: _,
                } => {
                    let _ = sender.send(block_id).log_err_pfx("The new tip receiver closed");
                }
            },
        );

    chainstate_handle
        .call_mut(|this| {
            this.subscribe_to_subsystem_events(subscribe_func);
            Ok(())
        })
        .await?;

    Ok(receiver)
}

/// Returns a receiver for the mempool `TransactionProcessed` events.
pub async fn subscribe_to_tx_processed(
    mempool_handle: &MempoolHandle,
) -> Result<UnboundedReceiver<TransactionProcessedEvent>> {
    let (sender, receiver) = mpsc::unbounded_channel();

    let subscribe_func = move |event: MempoolEvent| match event {
        MempoolEvent::TransactionProcessed(tpe) => {
            let _ = sender.send(tpe).log_err_pfx("The tx processed receiver closed");
        }
        MempoolEvent::NewTip(_) => (),
    };
    let subscribe_func = Arc::new(subscribe_func);

    mempool_handle
        .call_mut(|this| this.subscribe_to_subsystem_events(subscribe_func))
        .await
        .map_err(|_| P2pError::SubsystemFailure)?;

    Ok(receiver)
}

pub trait Observer: DynClone {
    /// This will be called on each iteration of PeerTransactionSyncManager's main loop
    /// (currently only used by Peer V2).
    fn on_transaction_sync_mgr_main_loop_iteration_completed(&mut self, peer_id: PeerId);
}

pub type BoxedObserver = Box<dyn Observer + Send + Sync>;

// Note: this makes Box<dyn Observer> clonable.
dyn_clone::clone_trait_object!(Observer);

#[cfg(test)]
mod tests;

#[cfg(test)]
pub mod test_helpers {
    pub use super::tests::helpers::*;
}
