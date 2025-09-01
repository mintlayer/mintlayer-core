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

use std::time::Duration;

use randomness::make_pseudo_rng;
use tokio::{
    sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender},
    time::{Instant, MissedTickBehavior},
};

use common::{
    chain::Transaction,
    primitives::{Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{MempoolHandle, TxOptions};
use utils::const_value::ConstValue;
use utils::sync::Arc;

use crate::{
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    message::{TransactionResponse, TransactionSyncMessage},
    net::{
        types::services::{Service, Services},
        NetworkingService,
    },
    sync::{
        chainstate_handle::ChainstateHandle,
        peer_common::{handle_message_processing_result, KnownTransactions},
        BoxedObserver, LocalEvent,
    },
    types::peer_id::PeerId,
    MessagingService, PeerManagerEvent, Result,
};

use super::{
    pending_transactions::PendingTransactions, requested_transactions::RequestedTransactions,
};

// TODO: add smaller interval for outbound connections
pub const TX_RELAY_DELAY_INTERVAL: Duration = Duration::from_secs(5);

// TODO: Take into account the chain work when syncing.
/// Transaction sync manager.
///
/// Syncing logic runs in a separate task for each peer.
pub struct PeerTransactionSyncManager<T: NetworkingService> {
    id: ConstValue<PeerId>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_msg_receiver: Receiver<TransactionSyncMessage>,
    local_event_receiver: UnboundedReceiver<LocalEvent>,
    /// A rolling filter of all known transactions (sent to us or sent by us)
    known_transactions: KnownTransactions,
    /// This tracks transactions that we've requested from this peer but for which we haven't
    /// received a response yet.
    requested_transactions: RequestedTransactions,
    /// Txs aren't relayed immediately but rather put into a collection to be propagated later
    /// with random delay to make tracing transactions' origin harder
    pending_transactions: PendingTransactions,
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
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        sync_msg_receiver: Receiver<TransactionSyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_receiver: UnboundedReceiver<LocalEvent>,
        time_getter: TimeGetter,
        observer: Option<BoxedObserver>,
    ) -> Self {
        let known_transactions = KnownTransactions::new();

        Self {
            id: id.into(),
            p2p_config,
            common_services,
            chainstate_handle,
            mempool_handle,
            peer_mgr_event_sender,
            messaging_handle,
            sync_msg_receiver,
            local_event_receiver,
            known_transactions,
            requested_transactions: RequestedTransactions::new(time_getter),
            pending_transactions: PendingTransactions::new(),
            observer,
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
        let peer_id = self.id();
        let maintenance_interval_duration = Duration::from_secs(1);
        let mut maintenance_interval = tokio::time::interval_at(
            Instant::now() + maintenance_interval_duration,
            maintenance_interval_duration,
        );
        maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            if let Some(o) = self.observer.as_mut() {
                o.on_new_transaction_sync_mgr_main_loop_iteration(peer_id);
            }

            tokio::select! {
                message = self.sync_msg_receiver.recv() => {
                    let message = message.ok_or(P2pError::ChannelClosed)?;
                    self.handle_message(message).await?;
                }

                event = self.local_event_receiver.recv() => {
                    let event = event.ok_or(P2pError::ChannelClosed)?;
                    self.handle_local_event(event)?;
                }

                _ = self.pending_transactions.due() => {
                    if let Some(new_tx) = self.pending_transactions.pop(){
                        self.send_message(TransactionSyncMessage::NewTransaction(new_tx))?;
                    }
                }

                _ = maintenance_interval.tick() => {}
            }

            self.requested_transactions.purge_if_needed();
        }
    }

    fn send_message(&mut self, message: TransactionSyncMessage) -> Result<()> {
        self.messaging_handle.send_transaction_sync_message(self.id(), message)
    }

    fn handle_local_event(&mut self, event: LocalEvent) -> Result<()> {
        log::debug!("Handling local peer mgr event: {event:?}");

        match event {
            LocalEvent::ChainstateNewTip(_) => Ok(()),
            LocalEvent::MempoolNewTx(txid) => {
                if !self.known_transactions.contains(&txid)
                    && self.common_services.has_service(Service::Transactions)
                {
                    self.add_known_transaction(txid);

                    // TODO: whitelisted peers should get txs without delay
                    let now = Instant::now();
                    let delay = TX_RELAY_DELAY_INTERVAL
                        .mul_f64(utils::exp_rand::exponential_rand(&mut make_pseudo_rng()));
                    self.pending_transactions.push(txid, now + delay);
                }
                Ok(())
            }
        }
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

    async fn handle_transaction_request(&mut self, id: Id<Transaction>) -> Result<()> {
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

        let tx = self.mempool_handle.call(move |m| m.transaction(&id)).await?;
        let res = match tx {
            Some(tx) => TransactionResponse::Found(tx),
            None => TransactionResponse::NotFound(id),
        };

        self.send_message(TransactionSyncMessage::TransactionResponse(res))?;

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
            log::warn!("Ignoring unsolicited TransactionResponse for tx {id}");
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
        log::debug!("Handling transaction announcement: {tx}");

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
            // Also, we don't punish the peer, mainly for consistency with other places, where
            // we handle requested_transactions-related mischiefs leniently.
            log::warn!("Ignoring duplicate announcement for tx {tx}");
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
            log::warn!("Ignoring announcement for tx {tx} because requested_transactions is over the limit");
            return Ok(());
        }

        if !(self.mempool_handle.call(move |m| m.contains_transaction(&tx)).await?) {
            self.send_message(TransactionSyncMessage::TransactionRequest(tx))?;
            self.requested_transactions.add(&tx);
        }

        Ok(())
    }
}
