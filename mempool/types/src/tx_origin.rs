// Copyright (c) 2023 RBB S.r.l
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

use p2p_types::peer_id::PeerId;

/// Tracks where a transaction originates
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum TxOrigin {
    /// Transaction originates locally
    Local(LocalTxOrigin),

    /// Transaction was received from a peer.
    Remote(RemoteTxOrigin),
}

impl From<LocalTxOrigin> for TxOrigin {
    fn from(value: LocalTxOrigin) -> Self {
        Self::Local(value)
    }
}

impl From<RemoteTxOrigin> for TxOrigin {
    fn from(value: RemoteTxOrigin) -> Self {
        Self::Remote(value)
    }
}

/// Signifies transaction originates in our local node
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum LocalTxOrigin {
    /// Transaction was submitted to local node's mempool. It should not be propagated further.
    Mempool,

    /// Transaction was submitted via local node's RPC subsystem. It should be propagated if valid.
    P2p,

    /// Transaction was in a block but moved into the mempool upon a reorg.
    PastBlock,
}

/// Transaction was received from a peer.
///
/// If it eventually turns out to be valid, it should be propagated further to other peers.
/// If it's not valid, the original peer should be penalized as appropriate.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct RemoteTxOrigin(PeerId);

impl RemoteTxOrigin {
    pub const fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    pub const fn peer_id(self) -> PeerId {
        self.0
    }
}

impl std::fmt::Display for TxOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxOrigin::Local(origin) => origin.fmt(f),
            TxOrigin::Remote(origin) => origin.fmt(f),
        }
    }
}

impl std::fmt::Display for LocalTxOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mempool => write!(f, "local node mempool"),
            Self::P2p => write!(f, "local node p2p"),
            Self::PastBlock => write!(f, "reorged-out block"),
        }
    }
}

impl std::fmt::Display for RemoteTxOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer node {}", self.0)
    }
}

/// Marker for origin types
pub trait IsOrigin: Copy + Eq + Ord + std::fmt::Debug + seal::IsOrigin {}
impl IsOrigin for TxOrigin {}
impl IsOrigin for LocalTxOrigin {}
impl IsOrigin for RemoteTxOrigin {}

mod seal {
    pub trait IsOrigin {}
    impl IsOrigin for super::TxOrigin {}
    impl IsOrigin for super::LocalTxOrigin {}
    impl IsOrigin for super::RemoteTxOrigin {}
}
