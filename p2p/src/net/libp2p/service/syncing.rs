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

use async_trait::async_trait;
use libp2p::{core::PeerId, gossipsub::MessageId, request_response::RequestId};
use tokio::sync::{mpsc, oneshot};

use logging::log;
use serialization::{Decode, Encode};

use crate::{
    error::{P2pError, ProtocolError},
    message,
    net::{
        libp2p::{
            behaviour::sync_codec::message_types::{SyncRequest, SyncResponse},
            types::{Command, SyncingEvent as P2pSyncingEvent},
        },
        types::{PubSubTopic, SyncingEvent, ValidationResult},
        NetworkingService, SyncingMessagingService,
    },
};

pub struct Libp2pSyncHandle<T: NetworkingService> {
    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::UnboundedSender<Command>,

    /// Channel for receiving pubsub events from libp2p backend
    sync_rx: mpsc::UnboundedReceiver<P2pSyncingEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: NetworkingService> Libp2pSyncHandle<T> {
    pub fn new(
        cmd_tx: mpsc::UnboundedSender<Command>,
        sync_rx: mpsc::UnboundedReceiver<P2pSyncingEvent>,
    ) -> Self {
        Self {
            cmd_tx,
            sync_rx,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<T> SyncingMessagingService<T> for Libp2pSyncHandle<T>
where
    T: NetworkingService<
            PeerId = PeerId,
            SyncingPeerRequestId = RequestId,
            SyncingMessageId = MessageId,
        > + Send,
{
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        request: message::Request,
    ) -> crate::Result<T::SyncingPeerRequestId> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::SendRequest {
            peer_id,
            request: Box::new(SyncRequest::new(request.encode())),
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn send_response(
        &mut self,
        request_id: T::SyncingPeerRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::SendResponse {
            request_id,
            response: Box::new(SyncResponse::new(response.encode())),
            channel: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn send_announcement(
        &mut self,
        topic: PubSubTopic,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let (response, rx) = oneshot::channel();
        self.cmd_tx.send(Command::AnnounceData {
            topic,
            message,
            response,
        })?;
        rx.await?
    }

    async fn subscribe(&mut self, topics: &[PubSubTopic]) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Subscribe {
            topics: topics.iter().map(|topic| topic.into()).collect::<Vec<_>>(),
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        message_id: T::SyncingMessageId,
        result: ValidationResult,
    ) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::ReportValidationResult {
            message_id,
            source,
            result: result.into(),
            response: tx,
        })?;

        // The first error indicates the channel being closed and the second one is a p2p error.
        rx.await?
    }

    async fn poll_next(&mut self) -> crate::Result<SyncingEvent<T>> {
        match self.sync_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            P2pSyncingEvent::Request {
                peer_id,
                request_id,
                request,
            } => {
                // TODO: decode  on libp2p side!
                let request = message::Request::decode(&mut &(*request)[..]).map_err(|err| {
                    log::error!("invalid request received from peer {}: {}", peer_id, err);
                    P2pError::ProtocolError(ProtocolError::InvalidMessage)
                })?;

                Ok(SyncingEvent::Request {
                    peer_id,
                    request_id,
                    request,
                })
            }
            P2pSyncingEvent::Response {
                peer_id,
                request_id,
                response,
            } => {
                // TODO: decode  on libp2p side!
                let response = message::Response::decode(&mut &(*response)[..]).map_err(|err| {
                    log::error!("invalid response received from peer {}: {}", peer_id, err);
                    P2pError::ProtocolError(ProtocolError::InvalidMessage)
                })?;

                Ok(SyncingEvent::Response {
                    peer_id,
                    request_id,
                    response,
                })
            }
            P2pSyncingEvent::Error {
                peer_id,
                request_id,
                error,
            } => Ok(SyncingEvent::Error {
                peer_id,
                request_id,
                error,
            }),
            // TODO: FIXME: Is this needed?..
            P2pSyncingEvent::Announcement {
                peer_id,
                message_id,
                announcement,
            } => Ok(SyncingEvent::Announcement {
                peer_id,
                message_id,
                announcement,
            }),
        }
    }
}
