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
};
use libp2p::request_response::{RequestResponseEvent, RequestResponseMessage};
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
                        .send(types::SyncingEvent::SyncRequest {
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
                    .send(types::SyncingEvent::SyncResponse {
                        peer_id: peer,
                        request_id,
                        response: Box::new(response),
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed),
            },
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                log::debug!("response sent, request id {:?}", request_id);
                Ok(())
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                // TODO: report to peer manager, should not be possible
                log::error!("outbound failure, destroy peer info, inform front-end");
                Ok(())
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                // TODO: report to peer manager,
                // https://docs.rs/libp2p-request-response/latest/libp2p_request_response/enum.InboundFailure.html
                log::error!("inbound failure, destroy peer info, inform front-end");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {}
}
