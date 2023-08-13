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

use common::{chain::GenBlock, primitives::Id};
use crypto::random::Rng;
use futures::{future::select_all, FutureExt};
use logging::log;
use p2p_types::PeerId;
use tokio::time;

use crate::{
    message::{SyncMessage, TransactionResponse},
    sync::tests::helpers::LONG_TIMEOUT,
};

use super::{get_random_hash, TestNode};

pub struct TestNodeGroup {
    data: Vec<NodeDataItem>,
    prevent_peer_manager_events: bool,
}

struct NodeDataItem {
    node: TestNode,
    delay_sync_messages_from: bool,
}

#[derive(Clone, Debug)]
pub struct SyncMessageWithNodeIdx {
    pub message: SyncMessage,
    pub sender_node_idx: usize,
    pub receiver_node_idx: usize,
}

#[allow(dead_code)]
#[derive(Eq, PartialEq)]
pub enum MsgAction {
    SendAndContinue,
    SendAndBreak,
    Break,
}

impl TestNodeGroup {
    pub fn new<H>(handles: H) -> Self
    where
        H: IntoIterator<Item = TestNode>,
    {
        let data: Vec<_> = handles
            .into_iter()
            .map(|h| NodeDataItem {
                node: h,
                delay_sync_messages_from: false,
            })
            .collect();
        let mut this = Self {
            data,
            // FIXME: make true the default?
            prevent_peer_manager_events: false,
        };
        this.init();
        this
    }

    fn init(&mut self) {
        for i in 0..self.data.len() {
            for j in 0..self.data.len() {
                if i != j {
                    let dest_peer_id = self.data[j].node.peer_id;
                    self.data[i].node.try_connect_peer(dest_peer_id);
                }
            }
        }
    }

    pub async fn join_subsystem_managers(self) {
        let mut data = self.data;
        for data_item in data.drain(..) {
            data_item.node.join_subsystem_manager().await;
        }
    }

    pub fn node(&self, idx: usize) -> &TestNode {
        &self.data[idx].node
    }

    /// Receive a SyncMessage from any peer for which delay_sync_messages_from is set to false.
    /// Panic if a timeout occurs.
    async fn receive_next_sync_message(&mut self) -> SyncMessageWithNodeIdx {
        // TODO: is there anode1.try_connect_peer(node2.peer_id);

        let mut sync_event_receivers: Vec<_> = self
            .data
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, data_item)| {
                if data_item.delay_sync_messages_from {
                    None
                } else {
                    Some((idx, &mut data_item.node.sync_event_receiver))
                }
            })
            .collect();
        assert!(!sync_event_receivers.is_empty());

        let combined_future = select_all(
            sync_event_receivers
                .iter_mut()
                .map(|(_, recv)| recv.recv().boxed())
                .collect::<Vec<_>>(),
        );

        let (receiver_peer_id_msg, future_idx, _) =
            time::timeout(LONG_TIMEOUT, combined_future).await.unwrap();
        let sender_node_idx = sync_event_receivers[future_idx].0;
        let (receiver_peer_id, msg) = receiver_peer_id_msg.unwrap();
        let receiver_node_idx = self.node_idx_by_peer_id(receiver_peer_id);

        SyncMessageWithNodeIdx {
            message: msg,
            sender_node_idx,
            receiver_node_idx,
        }
    }

    fn node_idx_by_peer_id(&self, id: PeerId) -> usize {
        self.data
            .iter()
            .enumerate()
            .find_map(|(idx, item)| {
                if item.node.peer_id == id {
                    Some(idx)
                } else {
                    None
                }
            })
            .unwrap()
    }

    /// Set the delay_sync_messages_from flag for the specified node; if the flag is true,
    /// the sync-message-exchanging functions will not propagate messages from that node.
    pub fn delay_sync_messages_from_node(&mut self, node_idx: usize, delay: bool) {
        self.data[node_idx].delay_sync_messages_from = delay;
    }

    // This is only used to prevent infinite loops.
    const MSG_COUNT_LIMIT: usize = 1_000_000;

    /// Exchange sync messages (waiting for them if needed) while the passed function
    /// returns SendAndContinue.
    /// The "context" parameter can be anything, it will be forwarded to the function as is.
    pub async fn exchange_sync_messages_while<F, Context>(
        &mut self,
        context: &mut Context,
        mut func: F,
    ) where
        F: FnMut(
            /*this:*/ &mut TestNodeGroup,
            /*context:*/ &mut Context,
            /*msg:*/ &SyncMessageWithNodeIdx,
        ) -> MsgAction,
    {
        let mut msg_count: usize = 0;

        loop {
            self.assert_no_peer_manager_events_if_needed();

            let msg = self.receive_next_sync_message().await;

            let msg_action = func(self, context, &msg);
            if msg_action == MsgAction::Break {
                break;
            }

            self.send_sync_message(msg).await;

            match msg_action {
                MsgAction::SendAndContinue => { /*do nothing*/ }
                MsgAction::SendAndBreak => break,
                MsgAction::Break => unreachable!(),
            }

            self.assert_no_peer_manager_events_if_needed();

            assert!(msg_count < Self::MSG_COUNT_LIMIT);
            msg_count += 1;
        }
    }

    /// Perform "1 round" of exchanging sync messages - exchange only the ones that are already
    /// in-flight or those that will be in-flight shortly, but don't wait for new messages.
    pub async fn exchange_sync_messages(&mut self, rng: &mut impl Rng) {
        // Use a non-existent transaction request as a sentinel to separate the already "in-flight"
        // messages from those that may appear in the process.
        let sentinel_tx_id = get_random_hash(rng).into();
        let sentinel_msg = SyncMessage::TransactionRequest(sentinel_tx_id);

        log::debug!("Using transaction {sentinel_tx_id} as a sentinel");

        let mut msg_count = 0;

        for i in 0..self.data.len() {
            if self.data[i].delay_sync_messages_from {
                continue;
            }

            let cur_peer_id = self.data[i].node.peer_id;

            {
                // Send the sentinel
                log::debug!("Sending sentinel transaction {sentinel_tx_id} to peer {cur_peer_id}");

                let tx_sender_peer_id = self
                    .data
                    .iter()
                    .find_map(|data_item| {
                        if data_item.node.peer_id != cur_peer_id {
                            Some(data_item.node.peer_id)
                        } else {
                            None
                        }
                    })
                    .unwrap();

                self.data[i].node.send_message(tx_sender_peer_id, sentinel_msg.clone()).await;
            }

            loop {
                self.assert_no_peer_manager_events_if_needed();

                let (dest_peer_id, sync_event) =
                    self.data[i].node.sync_event_receiver.recv().await.unwrap();

                // Send sync messages between peers
                match &sync_event {
                    SyncMessage::TransactionResponse(TransactionResponse::NotFound(tx_id))
                        if *tx_id == sentinel_tx_id =>
                    {
                        log::debug!("Sentinel transaction {tx_id} received by peer {cur_peer_id}");
                        break;
                    }
                    message => {
                        let dest_peer_idx = self.node_idx_by_peer_id(dest_peer_id);
                        let event_sender = self.data[dest_peer_idx]
                            .node
                            .connected_peers
                            .get(&cur_peer_id)
                            .unwrap();
                        event_sender.send(message.clone()).await.unwrap();
                    }
                }

                self.assert_no_peer_manager_events_if_needed();

                assert!(msg_count < Self::MSG_COUNT_LIMIT);
                msg_count += 1;
            }
        }
    }

    /// Exchange sync messages until all nodes are in sync at the specified best block.
    pub async fn sync_all(&mut self, required_best_block_id: &Id<GenBlock>, rng: &mut impl Rng) {
        let helper = async move {
            while !self.all_in_sync(required_best_block_id).await {
                self.exchange_sync_messages(rng).await;
            }
        };

        tokio::time::timeout(LONG_TIMEOUT, helper).await.unwrap();
    }

    pub async fn send_sync_message(&mut self, msg: SyncMessageWithNodeIdx) {
        let receiver_handle = &self.data[msg.receiver_node_idx].node;
        let sender_handle = &self.data[msg.sender_node_idx].node;
        let receiving_peer_msg_sender =
            receiver_handle.connected_peers.get(&sender_handle.peer_id).unwrap();

        receiving_peer_msg_sender.send(msg.message).await.unwrap();
    }

    pub async fn send_sync_messages<Msg>(&mut self, msg: Msg)
    where
        Msg: IntoIterator<Item = SyncMessageWithNodeIdx>,
    {
        for msg in msg.into_iter() {
            self.send_sync_message(msg).await;
        }
    }

    pub async fn all_in_sync(&self, required_best_block_id: &Id<GenBlock>) -> bool {
        let best_blocks_ids = futures::future::join_all(self.data.iter().map(|data_item| async {
            data_item
                .node
                .chainstate()
                .call(|this| this.get_best_block_id().unwrap())
                .await
                .unwrap()
        }))
        .await;
        best_blocks_ids
            .iter()
            .all(|best_block_id| best_block_id == required_best_block_id)
    }

    pub fn set_assert_no_peer_manager_events(&mut self, set: bool) {
        self.prevent_peer_manager_events = set;
    }

    fn assert_no_peer_manager_events_if_needed(&mut self) {
        if self.prevent_peer_manager_events {
            for data_item in &mut self.data {
                if let Ok(peer_event) = data_item.node.peer_manager_event_receiver.try_recv() {
                    panic!("Unexpected peer manager event: {peer_event:?}");
                }
            }
        }
    }
}
