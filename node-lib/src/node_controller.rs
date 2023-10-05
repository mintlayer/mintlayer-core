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

use std::fmt::Debug;

use subsystem::ShutdownTrigger;

/// Controller for the node subsystems.
/// It contains handles to the subsystems to be used by components
/// that are meant to control a new, such as a CLI, GUI or similar.
#[derive(Clone)]
pub struct NodeController {
    pub shutdown_trigger: ShutdownTrigger,
    pub chainstate: chainstate::ChainstateHandle,
    pub mempool: mempool::MempoolHandle,
    pub block_prod: blockprod::BlockProductionHandle,
    pub p2p: p2p::P2pHandle,
}

impl Debug for NodeController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteController (contents cannot be displayed)").finish()
    }
}
