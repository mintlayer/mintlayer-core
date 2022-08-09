// Copyright (c) 2021 RBB S.r.l
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

use std::error::Error;

/// High-level error type that is passed between the subsystems
/// to signal serious errors, e.g., the inability to establish
/// any outbound connections.
///
/// Each subsystem who wishes to propagate an error message to
/// the rest of the system must implement the `From` trait which
/// wraps the internal error into a `MintlayerError`.
///
/// ```ignore
/// impl From<SocketError> for MintlayerError {
///     fn from(e: SocketError) -> MintlayerError {
///         MintlayerError::NetworkError(Box::new(e))
///     }
/// }
/// ```
#[derive(Debug)]
pub enum MintlayerError {
    /// Generic network error that might have originated from P2P or RPC
    #[allow(unused)]
    NetworkError(Box<dyn Error>),
}
