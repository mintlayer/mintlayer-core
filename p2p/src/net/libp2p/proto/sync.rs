// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::{
    error::{self, P2pError},
    net::libp2p::{backend::Backend, types, SyncRequest, SyncResponse},
    net::RequestResponseError,
};
use libp2p::request_response::{
    InboundFailure, OutboundFailure, RequestResponseEvent, RequestResponseMessage,
};
use logging::log;

impl Backend {
    pub async fn on_sync_event(
        &mut self,
        event: RequestResponseEvent<SyncRequest, SyncResponse>,
    ) -> error::Result<()> {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    self.pending_reqs.insert(request_id, channel);
                    self.sync_tx
                        .send(types::SyncingEvent::Request {
                            peer_id: peer,
                            request_id,
                            request: Box::new(request),
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed)
                }
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => self
                    .sync_tx
                    .send(types::SyncingEvent::Response {
                        peer_id: peer,
                        request_id,
                        response: Box::new(response),
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed),
            },
            RequestResponseEvent::ResponseSent {
                peer: _,
                request_id,
            } => {
                log::debug!("response sent, request id {:?}", request_id);
                Ok(())
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                match error {
                    OutboundFailure::Timeout => self
                        .sync_tx
                        .send(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: RequestResponseError::Timeout,
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed),
                    OutboundFailure::ConnectionClosed => self
                        .sync_tx
                        .send(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: RequestResponseError::ConnectionClosed,
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed),
                    OutboundFailure::DialFailure => {
                        log::error!("CRITICAL: syncing code tried to dial peer");
                        Ok(())
                    }
                    OutboundFailure::UnsupportedProtocols => {
                        log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                        Ok(())
                    }
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                match error {
                    InboundFailure::Timeout => self
                        .sync_tx
                        .send(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: RequestResponseError::Timeout,
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed),
                    InboundFailure::ConnectionClosed => self
                        .sync_tx
                        .send(types::SyncingEvent::Error {
                            peer_id: peer,
                            request_id,
                            error: RequestResponseError::ConnectionClosed,
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed),
                    InboundFailure::ResponseOmission => {
                        log::error!("CRITICAL(??): response omitted!");
                        Ok(())
                    }
                    InboundFailure::UnsupportedProtocols => {
                        log::error!("CRITICAL: unsupported protocol should have been caught by peer manager");
                        Ok(())
                    }
                }
            }
        }
    }
}
