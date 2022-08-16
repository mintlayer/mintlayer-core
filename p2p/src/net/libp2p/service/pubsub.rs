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

use crate::{
    error::{P2pError, PublishError},
    message,
    net::{
        self,
        libp2p::{constants, types},
        types::{PubSubEvent, PubSubTopic},
        NetworkingService, PubSubService,
    },
};
use async_trait::async_trait;
use libp2p::{core::PeerId, gossipsub::MessageId};
use serialization::Encode;
use tokio::sync::{mpsc, oneshot};
use utils::ensure;

pub struct Libp2pPubSubHandle<T: NetworkingService> {
    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::UnboundedSender<types::Command>,

    /// Channel for receiving pubsub events from libp2p backend
    gossip_rx: mpsc::UnboundedReceiver<types::PubSubEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: NetworkingService> Libp2pPubSubHandle<T> {
    pub fn new(
        cmd_tx: mpsc::UnboundedSender<types::Command>,
        gossip_rx: mpsc::UnboundedReceiver<types::PubSubEvent>,
    ) -> Self {
        Self {
            cmd_tx,
            gossip_rx,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<T> PubSubService<T> for Libp2pPubSubHandle<T>
where
    T: NetworkingService<PeerId = PeerId, PubSubMessageId = MessageId> + Send,
{
    async fn publish(&mut self, announcement: message::Announcement) -> crate::Result<()> {
        let encoded = announcement.encode();
        ensure!(
            encoded.len() <= constants::GOSSIPSUB_MAX_TRANSMIT_SIZE,
            P2pError::PublishError(PublishError::MessageTooLarge(
                Some(encoded.len()),
                Some(constants::GOSSIPSUB_MAX_TRANSMIT_SIZE),
            ))
        );

        // TODO: transactions
        let topic = match &announcement {
            message::Announcement::Block(_) => net::types::PubSubTopic::Blocks,
        };

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::AnnounceData {
            topic,
            message: encoded,
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        message_id: T::PubSubMessageId,
        result: net::types::ValidationResult,
    ) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::ReportValidationResult {
            message_id,
            source,
            result: result.into(),
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn subscribe(&mut self, topics: &[PubSubTopic]) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Subscribe {
            topics: topics.iter().map(|topic| topic.into()).collect::<Vec<_>>(),
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn poll_next(&mut self) -> crate::Result<PubSubEvent<T>> {
        match self.gossip_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::PubSubEvent::Announcement {
                peer_id,
                message_id,
                announcement,
            } => Ok(PubSubEvent::Announcement {
                peer_id,
                message_id,
                announcement,
            }),
        }
    }
}
