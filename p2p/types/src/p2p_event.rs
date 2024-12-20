// Copyright (c) 2021-2022 RBB S.r.l
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

use std::sync::Arc;

use serde::Serialize;

use common::primitives::{semver::SemVer, user_agent::UserAgent};

use crate::{peer_id::PeerId, services::Services};

pub type P2pEventHandler = Arc<dyn Fn(P2pEvent) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum P2pEvent {
    PeerConnected {
        id: PeerId,
        services: Services,
        address: String,
        inbound: bool,
        user_agent: UserAgent,
        software_version: SemVer,
    },
    PeerDisconnected(PeerId),
}
