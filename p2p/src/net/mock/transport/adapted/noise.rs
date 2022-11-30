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

use std::time::Duration;

use futures::future::BoxFuture;
use snowstorm::NoiseStream;
use tokio::time::timeout;

use crate::{
    error::P2pError,
    net::mock::{peer::Role, transport::PeerStream},
};

use super::StreamAdapter;

// How much time is allowed to spend setting up (optionally) encrypted stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static NOISE_HANDSHAKE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

static NOISE_HANDSHAKE_PARAMS: once_cell::sync::Lazy<snowstorm::NoiseParams> =
    once_cell::sync::Lazy::new(|| NOISE_HANDSHAKE_PATTERN.parse().expect("valid pattern"));

pub struct NoiseEncryptionAdapter {
    local_key: snowstorm::Keypair,
}

impl std::fmt::Debug for NoiseEncryptionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseEncryptionAdapter").finish()
    }
}

impl Clone for NoiseEncryptionAdapter {
    fn clone(&self) -> Self {
        Self {
            local_key: snowstorm::Keypair {
                private: self.local_key.private.clone(),
                public: self.local_key.public.clone(),
            },
        }
    }
}

/// StreamAdapter that encrypts the data going through it with noise protocol
impl<T: PeerStream + 'static> StreamAdapter<T> for NoiseEncryptionAdapter {
    type Stream = snowstorm::NoiseStream<T>;

    fn new() -> Self {
        let local_key = snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
            .generate_keypair()
            .expect("key generation must succeed");
        Self { local_key }
    }

    fn handshake(&self, base: T, role: Role) -> BoxFuture<'static, crate::Result<Self::Stream>> {
        let local_key = self.clone().local_key;
        Box::pin(async move {
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

            let stream = timeout(HANDSHAKE_TIMEOUT, NoiseStream::handshake(base, state))
                .await
                .map_err(|err| P2pError::NoiseHandshakeError(err.to_string()))?
                .map_err(|err| P2pError::NoiseHandshakeError(err.to_string()))?;

            // Remote peer public key is available after handshake
            assert!(stream.get_state().get_remote_static().is_some());

            Ok(stream)
        })
    }
}

impl<T: PeerStream> PeerStream for snowstorm::NoiseStream<T> {}
