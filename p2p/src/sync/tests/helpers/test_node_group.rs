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

use futures::{FutureExt, future::select_all};
use itertools::Either;
use tokio::time;

use common::{chain::GenBlock, primitives::Id};
use logging::log;
use p2p_test_utils::LONG_TIMEOUT;
use p2p_types::PeerId;
use randomness::Rng;

use crate::{PeerManagerEvent, message::BlockSyncMessage};

use super::{TestNode, TestPeer, get_random_hash};

struct NodeDataItem {
    node: TestNode,
    delay_block_sync_messages_from: bool,
    connected_peers: BTreeMap<PeerId, TestPeer>,
}

/// A struct that represents a group of test nodes.
pub struct TestNodeGroup {
    data: Vec<NodeDataItem>,
    prevent_peer_manager_events: bool,
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
                delay_block_sync_messages_from: false,
                connected_peers: Default::default(),
            })
            .collect();
        let mut this = Self {
            data,
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
                    let dest_peer_protocol_version = self.data[j].node.protocol_version;
                    let peer = self.data[i]
                        .node
                        .try_connect_peer(dest_peer_id, dest_peer_protocol_version);
                    self.data[i].connected_peers.insert(dest_peer_id, peer);
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

    #[allow(dead_code)]
    pub fn node(&self, idx: usize) -> &TestNode {
        &self.data[idx].node
    }

    pub fn node_mut(&mut self, idx: usize) -> &mut TestNode {
        &mut self.data[idx].node
    }

    /// From any peer, receive either a `BlockSyncMessage` (but only if `delay_block_sync_messages_from`
    /// is set to false for the peer) or a `PeerManagerEvent`.
    /// Panic if a timeout occurs.
    async fn receive_next_block_sync_message_or_peer_manager_event(
        &mut self,
    ) -> Either<BlockSyncMessageWithNodeIdx, PeerManagerEventWithNodeIdx> {
        let futures: Vec<_> = self
            .data
            .iter_mut()
            .map(|node_data_item| {
                async {
                    tokio::select! {
                        msg = node_data_item.node.block_sync_msg_receiver.recv(),
                            if !node_data_item.delay_block_sync_messages_from =>
                        {
                            Either::Left(msg)
                        }
                        event = node_data_item.node.peer_manager_event_receiver.recv() => {
                            Either::Right(event)
                        }
                    }
                }
                .boxed()
            })
            .collect();
        assert!(!futures.is_empty());

        let combined_future = select_all(futures);

        let (msg_or_peer_mgr_event, future_idx, _) =
            time::timeout(LONG_TIMEOUT, combined_future).await.unwrap();

        match msg_or_peer_mgr_event {
            Either::Left(msg) => {
                let (receiver_peer_id, msg) = msg.unwrap();
                let receiver_node_idx = self.node_idx_by_peer_id(receiver_peer_id);

                Either::Left(BlockSyncMessageWithNodeIdx {
                    message: msg,
                    sender_node_idx: future_idx,
                    receiver_node_idx,
                })
            }
            Either::Right(event) => Either::Right(PeerManagerEventWithNodeIdx {
                event: event.unwrap(),
                sender_node_idx: future_idx,
            }),
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

    /// Set the delay_block_sync_messages_from flag for the specified node; if the flag is true,
    /// the sync-message-exchanging functions will not propagate messages from that node.
    pub fn delay_block_sync_messages_from_node(&mut self, node_idx: usize, delay: bool) {
        self.data[node_idx].delay_block_sync_messages_from = delay;
    }

    // This is only used to prevent infinite loops.
    const MSG_COUNT_LIMIT: usize = 1_000_000;

    /// Exchange block sync messages and receive peer manager events, waiting for them if needed,
    /// while the passed function returns SendAndContinue.
    /// The "context" parameter can be anything, it will be forwarded to the function as is.
    /// Note: when a peer manager event is received, nothing will be sent, so `SendAndContinue`
    /// just means "Send" in this case.
    pub async fn exchange_block_sync_messages_while_generic<F, Context>(
        &mut self,
        context: &mut Context,
        mut func: F,
    ) where
        F: AsyncFnMut(
            // This node group.
            &mut TestNodeGroup,
            // The context.
            &mut Context,
            // The message or event.
            // Note that the peer manager event has to be passed by value, since the caller may need
            // to send a confirmation using a one-shot sender contained in the event, which will consume
            // the sender (and PeerManagerEvent is non-clonable due to these senders).
            Either<&BlockSyncMessageWithNodeIdx, PeerManagerEventWithNodeIdx>,
        ) -> MsgAction,
    {
        let mut msg_count: usize = 0;

        loop {
            let msg_or_peer_mgr_event =
                self.receive_next_block_sync_message_or_peer_manager_event().await;

            let (msg, peer_mgr_event) = match msg_or_peer_mgr_event {
                Either::Left(msg) => (Some(msg), None),
                Either::Right(event) => (None, Some(event)),
            };

            let msg_action = func(
                self,
                context,
                msg.as_ref()
                    .map_or_else(|| Either::Right(peer_mgr_event.unwrap()), Either::Left),
            )
            .await;
            if msg_action == MsgAction::Break {
                break;
            }

            if let Some(msg) = msg {
                self.send_sync_message(msg).await;
            }

            match msg_action {
                MsgAction::SendAndContinue => { /*do nothing*/ }
                MsgAction::SendAndBreak => break,
                MsgAction::Break => unreachable!(),
            }

            assert!(msg_count < Self::MSG_COUNT_LIMIT);
            msg_count += 1;
        }
    }

    /// Exchange block sync messages, waiting for them if needed, while the passed function
    /// returns SendAndContinue.
    /// The "context" parameter can be anything, it will be forwarded to the function as is.
    pub async fn exchange_block_sync_messages_while<F, Context>(
        &mut self,
        context: &mut Context,
        mut func: F,
    ) where
        F: AsyncFnMut(
            /*this:*/ &mut TestNodeGroup,
            /*context:*/ &mut Context,
            /*msg:*/ &BlockSyncMessageWithNodeIdx,
        ) -> MsgAction,
    {
        self.exchange_block_sync_messages_while_generic(
            context,
            async |this, context, msg_or_peer_mgr_event| match msg_or_peer_mgr_event {
                Either::Left(msg) => func(this, context, msg).await,
                Either::Right(event) => {
                    if this.prevent_peer_manager_events {
                        Self::assert_informational_peer_mgr_event(&event.event)
                    }

                    MsgAction::SendAndContinue
                }
            },
        )
        .await
    }

    /// Perform "1 round" of exchanging block sync messages - exchange only the ones that are already
    /// in-flight or those that will be in-flight shortly, but don't wait for new messages.
    pub async fn exchange_block_sync_messages(&mut self, rng: &mut impl Rng) {
        let sentinel_id = get_random_hash(rng).into();
        let sentinel_msg = BlockSyncMessage::TestSentinel(sentinel_id);

        log::trace!("Using sentinel message with id {sentinel_id}");

        let mut msg_count = 0;

        for i in 0..self.data.len() {
            if self.data[i].delay_block_sync_messages_from {
                continue;
            }

            let cur_peer_id = self.data[i].node.peer_id;

            {
                // Send the sentinel
                log::trace!("Sending sentinel message with id {sentinel_id} to peer {cur_peer_id}");

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

                self.data[i].connected_peers[&tx_sender_peer_id]
                    .send_block_sync_message(sentinel_msg.clone())
                    .await;
            }

            loop {
                self.assert_no_non_informational_peer_manager_events_if_needed();

                let (dest_peer_id, sync_msg) =
                    self.data[i].node.block_sync_msg_receiver.recv().await.unwrap();

                // Send sync messages between peers
                match &sync_msg {
                    BlockSyncMessage::TestSentinel(id) if *id == sentinel_id => {
                        log::trace!(
                            "Sentinel message with id {sentinel_id} received by peer {cur_peer_id}"
                        );
                        break;
                    }
                    message => {
                        let dest_peer_idx = self.node_idx_by_peer_id(dest_peer_id);
                        let event_sender =
                            self.data[dest_peer_idx].connected_peers.get(&cur_peer_id).unwrap();
                        event_sender.send_block_sync_message(message.clone()).await;
                    }
                }

                self.assert_no_non_informational_peer_manager_events_if_needed();

                assert!(msg_count < Self::MSG_COUNT_LIMIT);
                msg_count += 1;
            }
        }
    }

    /// Exchange sync messages until all nodes are in sync at the specified best block.
    pub async fn sync_all(&mut self, required_best_block_id: &Id<GenBlock>, rng: &mut impl Rng) {
        let helper = async move {
            while !self.all_in_sync(required_best_block_id).await {
                self.exchange_block_sync_messages(rng).await;
            }
        };

        tokio::time::timeout(LONG_TIMEOUT, helper).await.unwrap();
    }

    pub async fn send_sync_message(&mut self, msg: BlockSyncMessageWithNodeIdx) {
        let receiver_handle = &self.data[msg.receiver_node_idx];
        let sender_handle = &self.data[msg.sender_node_idx].node;
        let receiving_peer_msg_sender =
            receiver_handle.connected_peers.get(&sender_handle.peer_id).unwrap();

        receiving_peer_msg_sender.send_block_sync_message(msg.message).await;
    }

    pub async fn send_sync_messages<Msg>(&mut self, msg: Msg)
    where
        Msg: IntoIterator<Item = BlockSyncMessageWithNodeIdx>,
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

    /// Call `assert_no_non_informational_peer_manager_events` if `prevent_peer_manager_events` was set to true.
    fn assert_no_non_informational_peer_manager_events_if_needed(&mut self) {
        if self.prevent_peer_manager_events {
            self.assert_no_non_informational_peer_manager_events()
        }
    }

    /// Assert there are no peer manager events except for the "informational" messages like
    /// NewTipReceived/NewChainstateTip etc.
    fn assert_no_non_informational_peer_manager_events(&mut self) {
        for data_item in &mut self.data {
            if let Ok(event) = data_item.node.peer_manager_event_receiver.try_recv() {
                Self::assert_informational_peer_mgr_event(&event)
            }
        }
    }

    fn assert_informational_peer_mgr_event(event: &PeerManagerEvent) {
        match event {
            PeerManagerEvent::Connect(_, _)
            | PeerManagerEvent::Disconnect(_, _, _, _)
            | PeerManagerEvent::GetPeerCount(_)
            | PeerManagerEvent::GetBindAddresses(_)
            | PeerManagerEvent::GetConnectedPeers(_)
            | PeerManagerEvent::AdjustPeerScore { .. }
            | PeerManagerEvent::GetReserved(_)
            | PeerManagerEvent::AddReserved(_, _)
            | PeerManagerEvent::RemoveReserved(_, _)
            | PeerManagerEvent::ListBanned(_)
            | PeerManagerEvent::Ban(_, _, _)
            | PeerManagerEvent::Unban(_, _)
            | PeerManagerEvent::ListDiscouraged(_)
            | PeerManagerEvent::Undiscourage(_, _)
            | PeerManagerEvent::EnableNetworking { .. }
            | PeerManagerEvent::GenericQuery(_)
            | PeerManagerEvent::GenericMut(_) => {
                panic!("Unexpected peer manager event: {event:?}");
            }
            PeerManagerEvent::NewTipReceived { .. }
            | PeerManagerEvent::NewChainstateTip(_)
            | PeerManagerEvent::NewValidTransactionReceived { .. }
            | PeerManagerEvent::PeerBlockSyncStatusUpdate { .. } => {
                // Ignored
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockSyncMessageWithNodeIdx {
    pub message: BlockSyncMessage,
    pub sender_node_idx: usize,
    pub receiver_node_idx: usize,
}

#[derive(Debug)]
pub struct PeerManagerEventWithNodeIdx {
    pub event: PeerManagerEvent,
    pub sender_node_idx: usize,
}

#[allow(dead_code)]
#[derive(Eq, PartialEq)]
pub enum MsgAction {
    SendAndContinue,
    SendAndBreak,
    Break,
}
