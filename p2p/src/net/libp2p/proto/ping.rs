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
    net::libp2p::backend::Backend,
};
use libp2p::ping::{self, PingEvent};
use logging::log;

impl Backend {
    pub async fn on_ping_event(&mut self, event: PingEvent) -> error::Result<()> {
        match event {
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Ping { rtt }),
            } => {
                // println!(
                //     "ping: rtt to {} is {} ms",
                //     peer.to_base58(),
                //     rtt.as_millis()
                // );
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Pong),
            } => {
                // println!("ping: pong from {}", peer.to_base58());
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Timeout),
            } => {
                // println!("ping: timeout to {}", peer.to_base58());
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Unsupported),
            } => {
                // println!("ping: {} does not support ping protocol", peer.to_base58());
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Other { error }),
            } => {
                // println!("ping: ping::Failure with {}: {}", peer.to_base58(), error);
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
