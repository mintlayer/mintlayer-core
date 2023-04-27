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

use blockprod::interface::blockprod_interface::BlockProductionInterface;
use chainstate_launcher::ChainstateInterface;
use mempool::MempoolInterface;
use p2p::interface::p2p_interface::P2pInterface;
use subsystem::{manager::ShutdownTrigger, Handle};

/// Controller for the node subsystems.
/// It contains handles to the subsystems to be used by components
/// that are meant to control a new, such as a CLI, GUI or similar.
#[derive(Clone)]
pub struct NodeController {
    pub shutdown_trigger: ShutdownTrigger,
    pub chainstate: Handle<Box<dyn ChainstateInterface>>,
    pub mempool: Handle<dyn MempoolInterface>,
    pub block_prod: Handle<Box<dyn BlockProductionInterface>>,
    pub p2p: Handle<Box<dyn P2pInterface>>,
}

impl Debug for NodeController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteController (contents cannot be displayed)").finish()
    }
}
