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
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{error::P2pError, net::mock::peer::Role};

use super::{StreamAdapter, StreamKey};

static NOISE_HANDSHAKE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

static NOISE_HANDSHAKE_PARAMS: once_cell::sync::Lazy<snowstorm::NoiseParams> =
    once_cell::sync::Lazy::new(|| NOISE_HANDSHAKE_PATTERN.parse().expect("valid pattern"));

#[derive(Debug)]
pub struct NoiseEncryptionAdapter {}

pub struct NoiseStreamKey {
    local_key: snowstorm::Keypair,
}

impl Clone for NoiseStreamKey {
    fn clone(&self) -> Self {
        Self {
            // snowstorm::Keypair does not implement Clone, clone it manually.
            local_key: snowstorm::Keypair {
                private: self.local_key.private.clone(),
                public: self.local_key.public.clone(),
            },
        }
    }
}

impl StreamKey for NoiseStreamKey {
    fn gen_new() -> Self {
        let local_key = snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
            .generate_keypair()
            .expect("key generation must succeed");
        NoiseStreamKey { local_key }
    }
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> StreamAdapter<T>
    for NoiseEncryptionAdapter
{
    type Stream = snowstorm::NoiseStream<T>;

    type StreamKey = NoiseStreamKey;

    async fn handshake(
        stream_key: &Self::StreamKey,
        base: T,
        role: Role,
    ) -> crate::Result<Self::Stream> {
        let state = match role {
            Role::Outbound => snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .local_private_key(&stream_key.local_key.private)
                .build_initiator()
                .expect("snowstorm builder must succeed"),
            Role::Inbound => snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .local_private_key(&stream_key.local_key.private)
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
