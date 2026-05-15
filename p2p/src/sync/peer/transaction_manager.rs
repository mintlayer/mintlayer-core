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

use std::{collections::BTreeSet, time::Duration};

use tokio::{
    sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender},
    time::MissedTickBehavior,
};

use common::{
    chain::Transaction,
    primitives::{Id, Idable},
    time_getter::{MonotonicTimeGetter, TimeGetter},
};
use logging::log;
use mempool::{MempoolHandle, TxOptions};
use networking::types::ConnectionDirection;
use randomness::make_pseudo_rng;
use utils::{const_value::ConstValue, sender_with_id::MpscUnboundedSenderWithId, sync::Arc};

use crate::{
    MessagingService, PeerManagerEvent, Result,
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    message::{TransactionResponse, TransactionSyncMessage},
    net::{
        NetworkingService,
        types::services::{Service, Services},
    },
    sync::{
        BoxedObserver,
        chainstate_handle::ChainstateHandle,
        peer_common::{KnownTransactions, handle_message_processing_result},
    },
    types::peer_id::PeerId,
};

use super::requested_transactions::RequestedTransactions;

pub const TX_RELAY_DELAY_INTERVAL_INBOUND: Duration = Duration::from_secs(5);
pub const TX_RELAY_DELAY_INTERVAL_OUTBOUND: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub enum PeerTransactionSyncManagerLocalEvent {
    /// SyncManager got a tx from the mempool that should be relayed to other peers
    /// (the tx is not necessarily a new one).
    MempoolRelayableTx(Id<Transaction>),

    /// There are some unconfirmed local txs that need to be re-announced.
    UnconfirmedLocalTxsReannouncement(Arc<BTreeSet<Id<Transaction>>>),
}

#[derive(Debug, Clone)]
pub enum PeerTransactionSyncManagerLocalNotification {
    /// The transaction has been sent to the peer.
    TransactionSent(Id<Transaction>),
}

type PeerTransactionSyncManagerLocalNotificationSender =
    MpscUnboundedSenderWithId<PeerId, PeerTransactionSyncManagerLocalNotification>;

// TODO: Take into account the chain work when syncing.
/// Transaction sync manager.
///
/// Syncing logic runs in a separate task for each peer.
pub struct PeerTransactionSyncManager<T: NetworkingService> {
    id: ConstValue<PeerId>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    direction: ConnectionDirection,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_msg_receiver: Receiver<TransactionSyncMessage>,
    local_event_receiver: UnboundedReceiver<PeerTransactionSyncManagerLocalEvent>,
    local_notification_sender: PeerTransactionSyncManagerLocalNotificationSender,
    monotonic_time_getter: MonotonicTimeGetter,

    /// A rolling filter of all known transactions (sent to us or sent by us)
    known_transactions: KnownTransactions,

    /// This tracks transactions that we've requested from this peer but for which we haven't
    /// received a response yet.
    requested_transactions: RequestedTransactions,

    /// Txs aren't announced immediately but rather put into a collection. The announcements
    /// happen in batches at random time intervals, this makes tracing transactions' origin harder.
    /// Note that we don't preserve the original order of the announcements, for the same reason.
    transactions_to_announce: BTreeSet<Id<Transaction>>,

    /// SyncManager's observer for use by tests.
    observer: Option<BoxedObserver>,
}

impl<T> PeerTransactionSyncManager<T>
where
    T: NetworkingService,
    T::MessagingHandle: MessagingService,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PeerId,
        common_services: Services,
        direction: ConnectionDirection,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        sync_msg_receiver: Receiver<TransactionSyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_receiver: UnboundedReceiver<PeerTransactionSyncManagerLocalEvent>,
        local_notification_sender: PeerTransactionSyncManagerLocalNotificationSender,
        time_getter: TimeGetter,
        monotonic_time_getter: MonotonicTimeGetter,
        observer: Option<BoxedObserver>,
    ) -> Self {
        let known_transactions = KnownTransactions::new();

        Self {
            id: id.into(),
            p2p_config,
            common_services,
            direction,
            chainstate_handle,
            mempool_handle,
            peer_mgr_event_sender,
            messaging_handle,
            sync_msg_receiver,
            local_event_receiver,
            local_notification_sender,
            monotonic_time_getter,
            known_transactions,
            requested_transactions: RequestedTransactions::new(time_getter),
            transactions_to_announce: BTreeSet::new(),
            observer,
        }
    }

    /// Returns an identifier of the peer associated with this task.
    pub fn id(&self) -> PeerId {
        *self.id
    }

    #[tracing::instrument(skip_all, name = "", fields(peer_id = %self.id()), level = tracing::Level::ERROR)]
    pub async fn run(&mut self) {
        match self.main_loop().await {
            // The unexpected "channel closed" error will be handled by the sync manager.
            Ok(()) | Err(P2pError::ChannelClosed) => {}
            Err(e) => panic!("{} peer task failed: {e:?}", self.id()),
        }
    }

    async fn main_loop(&mut self) -> Result<()> {
        let peer_id = self.id();

        let maintenance_interval_duration = Duration::from_secs(1);
        let mut maintenance_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + maintenance_interval_duration,
            maintenance_interval_duration,
        );
        maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut next_time_to_announce_txs =
            self.monotonic_time_getter.get_time() + self.make_random_tx_announcement_delay();

        loop {
            tokio::select! {
                message = self.sync_msg_receiver.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                event = self.local_event_receiver.recv() => {
                    let event = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_local_event(event)?;
                }

                _ = maintenance_interval.tick() => {}
            }

            self.requested_transactions.purge_if_needed();

            let now = self.monotonic_time_getter.get_time();

            if now >= next_time_to_announce_txs {
                self.announce_transactions().await?;

                next_time_to_announce_txs = now + self.make_random_tx_announcement_delay();
            }

            if let Some(o) = self.observer.as_mut() {
                o.on_transaction_sync_mgr_main_loop_iteration_completed(peer_id);
            }
        }
    }

    // TODO: whitelisted peers should get txs without delay,
    // see https://github.com/mintlayer/mintlayer-core/issues/1406.
    fn make_random_tx_announcement_delay(&self) -> Duration {
        let base_delay = match self.direction {
            ConnectionDirection::Inbound => TX_RELAY_DELAY_INTERVAL_INBOUND,
            ConnectionDirection::Outbound => TX_RELAY_DELAY_INTERVAL_OUTBOUND,
        };
        base_delay.mul_f64(utils::exp_rand::exponential_rand(&mut make_pseudo_rng()))
    }

    fn send_message(&mut self, message: TransactionSyncMessage) -> Result<()> {
        self.messaging_handle.send_transaction_sync_message(self.id(), message)
    }

    fn handle_local_event(&mut self, event: PeerTransactionSyncManagerLocalEvent) -> Result<()> {
        log::debug!("Handling local event: {event:?}");

        match event {
            PeerTransactionSyncManagerLocalEvent::MempoolRelayableTx(tx_id) => {
                self.enqueue_transactions_to_announce([tx_id]);
            }

            PeerTransactionSyncManagerLocalEvent::UnconfirmedLocalTxsReannouncement(tx_ids) => {
                // Note: no special handling for this case, i.e. each tx id still has to pass
                // the `known_transactions` filter for the re-announcement attempt to be made
                // (the re-announcement mostly targets peers that were not present when the tx
                // was first announced).
                self.enqueue_transactions_to_announce(tx_ids.iter().cloned());
            }
        }

        Ok(())
    }

    fn enqueue_transactions_to_announce(
        &mut self,
        tx_ids: impl IntoIterator<Item = Id<Transaction>>,
    ) {
        if self.common_services.has_service(Service::Transactions) {
            for tx_id in tx_ids.into_iter() {
                if !self.known_transactions.contains(&tx_id) {
                    self.transactions_to_announce.insert(tx_id);
                }
            }
        }
    }

    async fn announce_transactions(&mut self) -> Result<()> {
        let tx_ids = std::mem::take(&mut self.transactions_to_announce);
        log::debug!("Announcing {} transactions", tx_ids.len());

        let sorted_tx_ids = self
            .mempool_handle
            .call(move |m| {
                let mut tx_ids = tx_ids;

                // Remove transactions that are no longer in the mempool, otherwise the next call may fail.
                tx_ids.retain(|tx_id| m.transaction(tx_id).is_some());

                // Sort the txs so that they don't become orphans immediately on the peer's side.
                // Note:
                // 1) At the moment the mempool tx sorting only reflects utxo-based relationships.
                //    So, some txs may become orphans on the peer's side, but it shouldn't be a big
                //    deal, since we announce all txs at once and the peer will normally request them
                //    immediately.
                // 2) Ideally, we should limit the number of txs that are sent at a time, to put pressure
                //    against low-fee transactions during low-fee transaction floods (and this is where
                //    `get_best_tx_ids_by_score_and_ancestry`'s sorting by tx score will come in handy,
                //    which is redundant at the moment). But it's better to first improve mempool's
                //    tx sorting, to avoid creating "long-term" orphans on the peer's side.
                //    (note that in Bitcoin the max number of txs to announce at a time is
                //    INVENTORY_BROADCAST_TARGET, which is 70 at the moment, plus some small extra
                //    number based on the current number of unannounced txs, with the hard cap of
                //    INVENTORY_BROADCAST_MAX, which is 1000).
                m.get_best_tx_ids_by_score_and_ancestry(&tx_ids, tx_ids.len())
            })
            .await??;

        for tx_id in sorted_tx_ids {
            self.add_known_transaction(tx_id);
            self.send_message(TransactionSyncMessage::NewTransaction(tx_id))?;
        }

        Ok(())
    }

    async fn handle_message(&mut self, message: TransactionSyncMessage) -> Result<()> {
        log::trace!("Handling tx sync message from the peer: {message:?}");

        let res = match message {
            TransactionSyncMessage::NewTransaction(id) => {
                self.handle_transaction_announcement(id).await
            }
            TransactionSyncMessage::TransactionRequest(id) => {
                self.handle_transaction_request(id).await
            }
            TransactionSyncMessage::TransactionResponse(tx) => {
                self.handle_transaction_response(tx).await
            }
        };
        handle_message_processing_result(&self.peer_mgr_event_sender, self.id(), res).await
    }

    async fn handle_transaction_request(&mut self, tx_id: Id<Transaction>) -> Result<()> {
        // TODO: should we handle a request if we haven't actually announced the tx?
        // Currently we do.
        // Note that in bitcoin-core they don't answer requests for txs that didn't exist
        // in mempool before the last INV and which are not in the most recent block
        // (see PeerManagerImpl::FindTxForGetData), but they don't punish peers for such
        // requests either.

        if !self.common_services.has_service(Service::Transactions) {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "A transaction request is received, but this node doesn't have the corresponding service".to_owned(),
            )));
        }

        let tx = self.mempool_handle.call(move |m| m.transaction(&tx_id)).await?;
        let (response, will_send_tx) = match tx {
            Some(tx) => (TransactionResponse::Found(tx), true),
            None => (TransactionResponse::NotFound(tx_id), false),
        };

        self.send_message(TransactionSyncMessage::TransactionResponse(response))?;

        if will_send_tx {
            let _ = self
                .local_notification_sender
                .send(PeerTransactionSyncManagerLocalNotification::TransactionSent(tx_id));
        }

        Ok(())
    }

    async fn handle_transaction_response(&mut self, resp: TransactionResponse) -> Result<()> {
        let (id, tx) = match resp {
            TransactionResponse::NotFound(id) => (id, None),
            TransactionResponse::Found(tx) => (tx.transaction().get_id(), Some(tx)),
        };

        if self.requested_transactions.remove(&id).is_none() {
            // Don't punish peers for unsolicited tx responses.
            //
            // Note that in bitcoin they handle unsolicited tx responses for now, but there was
            // a proposal to start ignoring them.
            // E.g. see here https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-February/018391.html
            // and here https://github.com/bitcoin/bitcoin/pull/21224
            // Basically, the guys who proposed this wanted to enforce the existing INV/GETDATA
            // sequence for all nodes over the network (i.e. for wallets too).
            // One of the reasons behind it was to be able to mitigate CPU DoS due to some heavy
            // txs being sent. There were counterarguments though that it wouldn't help anyway.
            //
            // In our case this is mostly for consistency - if we already have the request/response
            // mechanism, we should enforce it.
            // On the other hand, we can't punish peers for sending unsolicited responses,
            // because we purge "requested_transactions" from time to time. So it's technically
            // possible for such a response to be "solicited" but forgotten later.
            // So we just ignore the response.
            log::warn!("Ignoring unsolicited TransactionResponse for tx {id:x}");
            return Ok(());
        }

        if let Some(transaction) = tx {
            let origin = mempool::tx_origin::RemoteTxOrigin::new(self.id());
            let options = TxOptions::default_for(origin.into());
            let txid = transaction.transaction().get_id();
            let tx_status = self
                .mempool_handle
                .call_mut(move |m| m.add_transaction_remote(transaction, origin, options))
                .await??;
            match tx_status {
                mempool::TxStatus::InMempool => {
                    self.peer_mgr_event_sender.send(
                        PeerManagerEvent::NewValidTransactionReceived {
                            peer_id: self.id(),
                            txid,
                        },
                    )?;
                }
                mempool::TxStatus::InMempoolDuplicate
                | mempool::TxStatus::InOrphanPool
                | mempool::TxStatus::InOrphanPoolDuplicate => {}
            }
        }

        Ok(())
    }

    fn add_known_transaction(&mut self, txid: Id<Transaction>) {
        self.known_transactions.insert(&txid);
    }

    async fn handle_transaction_announcement(&mut self, tx: Id<Transaction>) -> Result<()> {
        log::debug!("Handling transaction announcement: {tx:x}");

        self.add_known_transaction(tx);

        if self.chainstate_handle.is_initial_block_download().await? {
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

        if self.requested_transactions.contains(&tx) {
            // Ignore duplicate announcements.
            //
            // Note: in bitcoin-core they also ignore them, because of the following:
            // First of all, they don't download the same tx from multiple peers, to save traffic.
            // And since the peer may not respond to a tx request, they have a timeout
            // (GETDATA_TX_INTERVAL, currently equal to 1 min) after which they ask another peer
            // for the same tx. Because of this, a tx censorship attack is possible, where the
            // attacker sends a tx announcement, but doesn't respond to the tx request, effectively
            // preventing the node from receiving the tx from any peer for 1 min. If duplicate
            // tx announcements were allowed in this scenario, the attacker could potentially
            // extend this "censorship" period indefinitely.
            // They still don't punish the peer though.
            //
            // In our case, this is not that important, at least not until we implement a similar
            // kind of tx request de-duplication.
            // But still, it doesn't make sense to request an already requested tx again.
            // Also, we don't punish the peer, because there are valid scenarios where a node may
            // want to re-broadcast a tx; and since the rolling bloom filter used to track known
            // txs can have false negatives, it's possible for a well-functioning peer to announce
            // the same tx twice.
            log::info!("Ignoring duplicate announcement for tx {tx:x}");
            return Ok(());
        }

        if self.requested_transactions.count()
            >= *self.p2p_config.protocol_config.max_peer_tx_announcements
        {
            // Note: a peer that sends tx announcements, but doesn't respond to tx requests
            // is behaving in a shady way, so we want to track that.
            // On the other hand, we don't want to punish it for exceeding the limit, because
            // otherwise we'd have to count tx announcements in the sending code as well
            // to prevent peers from banning us when we relay a large number of txs.
            // This seems overly complicated, so we just ignore peer's tx announcements
            // in such a situation. Note that after certain time, older requests will be purged
            // from requested_transactions, after which we'll start to handle peer's tx
            // announcements again.
            log::warn!(
                "Ignoring announcement for tx {tx:x} because requested_transactions is over the limit"
            );
            return Ok(());
        }

        if !(self.mempool_handle.call(move |m| m.contains_transaction(&tx)).await?) {
            self.send_message(TransactionSyncMessage::TransactionRequest(tx))?;
            self.requested_transactions.add(&tx);
        }

        Ok(())
    }
}
