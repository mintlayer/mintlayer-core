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

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use snowstorm::NoiseStream;
use tokio::time::timeout;

use crate::{
    error::P2pError,
    net::{mock::transport::PeerStream, types::Role},
};

use super::StreamAdapter;

// How much time is allowed to spend setting up (optionally) encrypted stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static NOISE_HANDSHAKE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

static NOISE_HANDSHAKE_PARAMS: once_cell::sync::Lazy<snowstorm::NoiseParams> =
    once_cell::sync::Lazy::new(|| NOISE_HANDSHAKE_PATTERN.parse().expect("valid pattern"));

#[derive(Clone)]
pub struct NoiseEncryptionAdapter {
    local_key: Arc<snowstorm::Keypair>,
}

impl NoiseEncryptionAdapter {
    pub fn gen_new() -> Self {
        let local_key = Arc::new(
            snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .generate_keypair()
                .expect("key generation must succeed"),
        );
        Self { local_key }
    }
}

impl std::fmt::Debug for NoiseEncryptionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseEncryptionAdapter").finish()
    }
}

/// StreamAdapter that encrypts the data going through it with noise protocol
impl<T: PeerStream + 'static> StreamAdapter<T> for NoiseEncryptionAdapter {
    type Stream = snowstorm::NoiseStream<T>;

    fn handshake(&self, base: T, role: Role) -> BoxFuture<'static, crate::Result<Self::Stream>> {
        let local_key = Arc::clone(&self.local_key);
        Box::pin(async move {
            let builder = snowstorm::Builder::new(NOISE_HANDSHAKE_PARAMS.clone())
                .local_private_key(&local_key.private);
            let state = match role {
                Role::Outbound => builder.build_initiator(),
                Role::Inbound => builder.build_responder(),
            }
            .expect("snowstorm builder must succeed");

            let stream = timeout(HANDSHAKE_TIMEOUT, NoiseStream::handshake(base, state))
                .await
                .map_err(|_err| P2pError::NoiseHandshakeError("Handshake timeout".to_owned()))?
                .map_err(|err| P2pError::NoiseHandshakeError(err.to_string()))?;

            // Remote peer public key is available after handshake
            assert!(stream.get_state().get_remote_static().is_some());

            Ok(stream)
        })
    }
}

impl<T: PeerStream> PeerStream for snowstorm::NoiseStream<T> {}
