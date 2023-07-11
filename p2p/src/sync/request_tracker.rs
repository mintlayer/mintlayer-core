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

use std::collections::BTreeMap;

use common::{chain::Transaction, primitives::Id};
use futures::never::Never;
use logging::log;
use tokio::sync::mpsc;

use crate::{
    sync::types::{PeerEvent, RequestTrackerEvent},
    types::peer_id::PeerId,
    utils::oneshot_queue::OneshotQueue,
};

/// Request tracker is responsible for tracking resource requests among peers.
///
/// For example, we may receive identical transaction announcements from multiple peers
/// concurrently. We want to only allow a single in-flight transaction body request. For that, a
/// peer must first get a permit from request tracker before executing the request.
pub struct RequestTracker {
    peer_event_receiver: mpsc::UnboundedReceiver<PeerEvent>,

    /// Channel for communication between peers and request tracker.
    request_tracker_receiver: mpsc::UnboundedReceiver<RequestTrackerEvent>,

    // Map of transactions for which we need to request a body.
    pending_transaction_requests: BTreeMap<Id<Transaction>, OneshotQueue<PeerId>>,
}

impl RequestTracker {
    pub fn new(
        peer_event_receiver: mpsc::UnboundedReceiver<PeerEvent>,
        request_tracker_receiver: mpsc::UnboundedReceiver<RequestTrackerEvent>,
    ) -> Self {
        Self {
            peer_event_receiver,
            request_tracker_receiver,
            pending_transaction_requests: BTreeMap::new(),
        }
    }

    pub async fn run(mut self) -> Never {
        log::info!("Starting request tracker");

        loop {
            tokio::select! {
                event = self.peer_event_receiver.recv() => {
                    if let Some(event) = event {
                        self.handle_peer_event(event);
                    }
                },

                event = self.request_tracker_receiver.recv() => {
                    if let Some(event) = event {
                        self.handle_request_tracker_event(event);
                    }
                },
            }
        }
    }

    fn handle_peer_event(&mut self, event: PeerEvent) {
        match event {
            PeerEvent::Disconnected(peer_id) => {
                self.remove_pending_transaction_requests_for_peer(peer_id);
            }
        }
    }

    fn handle_request_tracker_event(&mut self, event: RequestTrackerEvent) {
        match event {
            RequestTrackerEvent::RequestTransactionPermit(payload) => {
                let requests = &mut self.pending_transaction_requests;
                match requests.get_mut(&payload.tx_id) {
                    Some(queue) => {
                        // The transaction is in progress. Enqueue this peer transaction request.
                        payload.allow_tx.send(queue.enqueue(payload.peer_id))
                    }
                    None => {
                        // The transaction is not in progress. Create a queue for processing peer
                        // transaction requests.
                        let mut queue = OneshotQueue::new();
                        // Enqueue the peer.
                        payload.allow_tx.send(queue.enqueue(payload.peer_id));
                        // Allow the enqueued peer to immediately process.
                        queue.send_dequeue();
                        requests.insert(payload.tx_id, queue);
                    }
                }
            }
            RequestTrackerEvent::CompleteTransaction(payload) => {
                let requests = &mut self.pending_transaction_requests;
                match payload.result {
                    Ok(_) => {
                        // If the transaction was processed successfully, remove it from the map.
                        // Remaining waiters get automatically cancelled after drop.
                        requests.remove(&payload.tx_id);
                    }
                    Err(_) => {
                        // If the transaction failed, notify the next peer in the queue, if any.
                        let Some(queue) = requests.get_mut(&payload.tx_id) else {
                            return;
                        };

                        if queue.send_dequeue().is_some() {
                            log::debug!(
                                "failed to request transaction {} from peer {}; trying next peer",
                                payload.tx_id,
                                payload.peer_id,
                            );
                        } else {
                            log::warn!(
                                "failed to request transaction {} from peer {}; no more peers \
                                available for the transaction",
                                payload.tx_id,
                                payload.peer_id,
                            );
                            requests.remove(&payload.tx_id);
                        }
                    }
                }
            }
        }
    }

    fn remove_pending_transaction_requests_for_peer(&mut self, peer_id: PeerId) {
        let requests = &mut self.pending_transaction_requests;
        let mut tx_to_remove = vec![];
        for (tx_id, gate) in requests.iter_mut() {
            if gate.remove(&peer_id).is_none() && gate.send_dequeue().is_none() {
                tx_to_remove.push(*tx_id);
            }
        }
        for tx in tx_to_remove {
            requests.remove(&tx);
        }
    }
}
