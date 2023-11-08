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

use std::collections::BTreeSet;

use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};

use common::{
    chain::{ChainConfig, Transaction},
    primitives::{Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::MempoolHandle;
use utils::const_value::ConstValue;
use utils::sync::Arc;

use crate::{
    config::P2pConfig,
    error::{P2pError, ProtocolError},
    message::{TransactionResponse, TxSyncMessage},
    net::{
        types::services::{Service, Services},
        NetworkingService,
    },
    sync::{
        chainstate_handle::ChainstateHandle,
        peer_common::{handle_message_processing_result, KnownTransactions},
        LocalEvent,
    },
    types::peer_id::PeerId,
    MessagingService, PeerManagerEvent, Result,
};

// TODO: Take into account the chain work when syncing.
/// Transaction sync manager.
///
/// Syncing logic runs in a separate task for each peer.
pub struct PeerTxSyncManager<T: NetworkingService> {
    id: ConstValue<PeerId>,
    _chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    common_services: Services,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
    messaging_handle: T::MessagingHandle,
    sync_msg_receiver: Receiver<TxSyncMessage>,
    local_event_receiver: UnboundedReceiver<LocalEvent>,
    _time_getter: TimeGetter,
    /// A rolling filter of all known transactions (sent to us or sent by us)
    known_transactions: KnownTransactions,
    /// A list of transactions that have been announced by this peer. An entry is added when the
    /// identifier is announced and removed when the actual transaction or not found response is received.
    announced_transactions: BTreeSet<Id<Transaction>>,
}

impl<T> PeerTxSyncManager<T>
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
        peer_mgr_event_sender: UnboundedSender<PeerManagerEvent>,
        sync_msg_receiver: Receiver<TxSyncMessage>,
        messaging_handle: T::MessagingHandle,
        local_event_receiver: UnboundedReceiver<LocalEvent>,
        time_getter: TimeGetter,
    ) -> Self {
        let known_transactions = KnownTransactions::new();

        Self {
            id: id.into(),
            _chain_config: chain_config,
            p2p_config,
            common_services,
            chainstate_handle,
            mempool_handle,
            peer_mgr_event_sender,
            messaging_handle,
            sync_msg_receiver,
            local_event_receiver,
            _time_getter: time_getter,
            known_transactions,
            announced_transactions: BTreeSet::new(),
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
            }
        }
    }

    fn send_message(&mut self, message: TxSyncMessage) -> Result<()> {
        self.messaging_handle.send_tx_sync_message(self.id(), message)
    }

    fn handle_local_event(&mut self, event: LocalEvent) -> Result<()> {
        log::debug!(
            "[peer id = {}] Handling local peer mgr event: {event:?}",
            self.id()
        );

        match event {
            LocalEvent::ChainstateNewTip(_) => Ok(()),
            LocalEvent::MempoolNewTx(txid) => {
                if !self.known_transactions.contains(&txid)
                    && self.common_services.has_service(Service::Transactions)
                {
                    self.add_known_transaction(txid);
                    self.send_message(TxSyncMessage::NewTransaction(txid))
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn handle_message(&mut self, message: TxSyncMessage) -> Result<()> {
        log::trace!(
            "[peer id = {}] Handling tx sync message from the peer: {message:?}",
            self.id()
        );

        let res = match message {
            TxSyncMessage::NewTransaction(id) => self.handle_transaction_announcement(id).await,
            TxSyncMessage::TransactionRequest(id) => self.handle_transaction_request(id).await,
            TxSyncMessage::TransactionResponse(tx) => self.handle_transaction_response(tx).await,
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

        self.send_message(TxSyncMessage::TransactionResponse(res))?;

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
                    self.peer_mgr_event_sender.send(
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

    // TODO: This can be optimized, e.g. by implementing something similar to bitcoin's
    // TxRequestTracker, see https://github.com/mintlayer/mintlayer-core/issues/829
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

        if self.announced_transactions.len()
            >= *self.p2p_config.protocol_config.max_peer_tx_announcements
        {
            // Note:
            // 1. We don't punish peers for exceeding the limit. If we did, we'd have to also
            // take the limit into account when announcing transactions. Otherwise, it'd be
            // possible for a group of malicious peers to make honest peers ban us: they could
            // send us (max-1) transactions each, which we'd relay to honest peers. If the total
            // number of transactions is large, so that honest peers are not able to get
            // transaction responses fast enough, we'd exceed the limit and they'd ban us.
            //
            // 2. "announced_transactions" grows when a transaction request is made by the node
            // (so it's more like "requested_transactions") and shrinks when the peer replies.
            // So by not punishing peers here we basically allow them to ignore transaction
            // requests and for each ignored request "announced_transactions"'s size will
            // be increased by 1 forever (i.e. until the peer disconnects). Though this is not
            // nice, it's not a serious issue either, because "announced_transactions" will stop
            // growing after it reaches "max_peer_tx_announcements" elements (which is 5000 at the
            // moment), after which all further tx announcements from the peer will be ignored.
            // So the worst thing an attacker can do is eat up 5000*size_of(tx_id) bytes of memory
            // on the node per peer, which is insignificant.
            //
            // TODO: the "announced_transactions" mechanism needs a revamp. But we also have a TODO
            // above about introducing something similar to bitcoin's TxRequestTracker to optimize
            // bandwidth. This can replace "announced_transactions" as well.
            //
            // In any case, there are some questions that must be answered before starting
            // the revamp:
            // 1. Do we actually need a separate message for transaction announcement, why not send
            // it right away? (in which case TransactionResponse should probably become just
            // Transaction).
            // 2. Should we punish peers for sending unsolicited TransactionResponse's? (if not,
            // then again, it should probably become just Transaction).
            // Note that bitcoin-core does use separate messages: INV is used for announcements,
            // GETDATA for requests and TX for responses, but peers are not punished for
            // unsolicited TX messages.
            // (note that using something similar to INV, where multiple tx announcements are sent
            // at once, should be good for privacy, especially if there is an ability to delay
            // sending a particular tx announcement until some future INV)
            // 3. How the max_peer_tx_announcements limit has to be handled? Bitcoin-core has
            // a similar constant MAX_PEER_TX_ANNOUNCEMENTS; if it's reached, the further
            // announcements are ignored, but only if the peer doesn't have the "Relay" permission,
            // in which case any number of announcements seems to be allowed. But they also have
            // the ability to delay the relaying if there are too many transactions in-flight from
            // that peer (see PeerManagerImpl::AddTxAnnouncement).
            // 4. Should we punish peers for duplicated transaction announcements?
            // Bitcoin-core doesn't do that, but it also avoids requesting the same transaction
            // twice from the same peer, see the large comment in txrequest.h ("The same transaction
            // is never requested twice ..."). The stated reason for that is to make "transaction
            // censoring attacks" harder to perform, but it's not clear whether it's relevant for us
            // as well.
            //
            // To summarize, we should decide what the real purpose of this mechanism should be
            // in our case, and then revamp it accordingly.
            return Ok(());
        }

        if self.announced_transactions.contains(&tx) {
            return Err(P2pError::ProtocolError(
                ProtocolError::DuplicatedTransactionAnnouncement(tx),
            ));
        }

        if !(self.mempool_handle.call(move |m| m.contains_transaction(&tx)).await?) {
            self.send_message(TxSyncMessage::TransactionRequest(tx))?;
            assert!(self.announced_transactions.insert(tx));
        }

        Ok(())
    }
}
