// Copyright (c) 2025 RBB S.r.l
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

//! Podman driver for speculos execution, runs a speculos instance within
//! a Podman container.

use core::fmt::Debug;
use std::net::SocketAddr;

use crate::signer::ledger_signer::speculos::Handle;

use async_trait::async_trait;

/// Handle to a Speculos instance running under Podman
#[derive(Debug)]
pub struct PodmanHandle {
    addr: SocketAddr,
}

impl PodmanHandle {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

#[async_trait]
impl Handle for PodmanHandle {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}
