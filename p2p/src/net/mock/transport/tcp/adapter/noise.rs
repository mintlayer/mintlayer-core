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
use snowstorm::NoiseStream;
use tokio::net::TcpStream;

use crate::{error::P2pError, net::mock::peer::Role};

use super::StreamAdapter;

static NOISE_HANDSHAKE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

static NOISE_HANDSHAKE_PARAMS: once_cell::sync::Lazy<snowstorm::NoiseParams> =
    once_cell::sync::Lazy::new(|| NOISE_HANDSHAKE_PATTERN.parse().expect("valid pattern"));

#[derive(Debug)]
pub struct NoiseEncryptionAdapter {}

#[async_trait]
impl StreamAdapter for NoiseEncryptionAdapter {
    type Stream = snowstorm::NoiseStream<TcpStream>;

    async fn handshake(base: TcpStream, role: Role) -> crate::Result<Self::Stream> {
        // TODO: Check the data directory first, and use keys from there if available
        let local_key = snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
            .generate_keypair()
            .expect("key generation must succeed");

        let state = match role {
            Role::Outbound => snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .local_private_key(&local_key.private)
                .build_initiator()
                .expect("snowstorm builder must succeed"),
            Role::Inbound => snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .local_private_key(&local_key.private)
                .build_responder()
                .expect("snowstorm builder must succeed"),
        };

        let stream = NoiseStream::handshake(base, state)
            .await
            .map_err(|err| P2pError::NoiseHandshakeError(err.to_string()))?;

        // Remote peer public key is available after handshake
        assert!(stream.get_state().get_remote_static().is_some());

        Ok(stream)
    }
}
