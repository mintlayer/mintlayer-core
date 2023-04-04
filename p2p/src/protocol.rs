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

/// Network protocol version
///
/// When two nodes connect, they exchange protocol versions,
/// and the minimum version is selected as the negotiated network protocol version.
pub type NetworkProtocol = u32;

/// Initial protocol version
pub const NETWORK_PROTOCOL_V1: NetworkProtocol = 1;

/// Latest known network protocol version
pub const NETWORK_PROTOCOL_CURRENT: NetworkProtocol = NETWORK_PROTOCOL_V1;

/// Minimum supported network protocol version
pub const NETWORK_PROTOCOL_MIN: NetworkProtocol = NETWORK_PROTOCOL_V1;
