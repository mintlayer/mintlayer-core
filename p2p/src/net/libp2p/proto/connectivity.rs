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
    net::libp2p::backend::{Backend, PendingState},
};
use futures::StreamExt;
use libp2p::{core::connection::ConnectedPoint, swarm::DialError, PeerId};
use logging::log;

impl Backend {
    pub async fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    ) -> error::Result<()> {
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                log::trace!("connection established (dialer), peer id {:?}", peer_id);

                match self.pending_conns.remove(&peer_id) {
                    Some(PendingState::Dialed { tx }) => {
                        self.pending_conns.insert(peer_id, PendingState::OutboundAccepted { tx });
                    }
                    Some(state) => log::error!(
                        "connection state is invalid. Expected `Dialed`, got {:?}",
                        state
                    ),
                    None => log::error!("peer {:?} does not exist", peer_id),
                }

                Ok(())
            }
            ConnectedPoint::Listener {
                local_addr: _,
                send_back_addr,
            } => {
                log::trace!("connection established (listener), peer id {:?}", peer_id);

                match self.pending_conns.remove(&peer_id) {
                    Some(state) => {
                        // TODO: is this an actual error?
                        log::error!("peer {:?} already has active connection!", peer_id);
                    }
                    None => {
                        self.pending_conns.insert(
                            peer_id,
                            PendingState::InboundAccepted {
                                addr: send_back_addr,
                            },
                        );
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn on_outgoing_connection_error(
        &mut self,
        peer_id: Option<PeerId>,
        error: DialError,
    ) -> error::Result<()> {
        if let Some(peer_id) = peer_id {
            match self.pending_conns.remove(&peer_id) {
                Some(PendingState::Dialed { tx }) | Some(PendingState::OutboundAccepted { tx }) => {
                    tx.send(Err(P2pError::SocketError(
                        std::io::ErrorKind::ConnectionRefused,
                    )))
                    .map_err(|_| P2pError::ChannelClosed)
                }
                _ => {
                    log::debug!("connection failed for peer {:?}: {:?}", peer_id, error);
                    Ok(())
                }
            }
        } else {
            log::error!("unhandled connection error: {:#?}", error);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {}
}
