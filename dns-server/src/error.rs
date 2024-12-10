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

use std::net::AddrParseError;

use hickory_client::proto::error::ProtoError;
use p2p::{error::P2pError, peer_manager::peerdb_common};
use thiserror::Error;
use utils::try_as::TryAsRef;

#[derive(Error, Debug)]
pub enum DnsServerError {
    #[error("Proto error: {0}")]
    ProtoError(#[from] ProtoError),
    #[error("Parse error: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("P2P error: {0}")]
    P2pError(#[from] P2pError),
    #[error("Storage error: {0}")]
    StorageError(#[from] storage::Error),
    #[error("Other: `{0}`")]
    Other(&'static str),
    #[error("The storage state is invalid: {0}")]
    InvalidStorageState(String),
    #[error("Storage version mismatch: expected {expected_version}, got {actual_version}")]
    StorageVersionMismatch {
        expected_version: peerdb_common::StorageVersion,
        actual_version: peerdb_common::StorageVersion,
    },
}

impl TryAsRef<storage::Error> for DnsServerError {
    fn try_as_ref(&self) -> Option<&storage::Error> {
        match self {
            DnsServerError::ProtoError(_)
            | DnsServerError::AddrParseError(_)
            | DnsServerError::IoError(_)
            | DnsServerError::P2pError(_)
            | DnsServerError::Other(_)
            | DnsServerError::InvalidStorageState(_)
            | DnsServerError::StorageVersionMismatch {
                expected_version: _,
                actual_version: _,
            } => None,
            DnsServerError::StorageError(err) => Some(err),
        }
    }
}
