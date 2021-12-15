// Copyright (c) 2021 RBB S.r.l
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
#[derive(Debug, PartialEq)]
pub enum P2pError {
    SocketError(std::io::ErrorKind),
    PeerDisconnected,
    DecodeFailure(String),
}

pub type Result<T> = core::result::Result<T, P2pError>;

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> P2pError {
        P2pError::SocketError(e.kind())
    }
}

impl From<parity_scale_codec::Error> for P2pError {
    fn from(e: parity_scale_codec::Error) -> P2pError {
        P2pError::DecodeFailure(e.to_string())
    }
}
