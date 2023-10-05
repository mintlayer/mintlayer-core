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

//! This module is responsible for both initial syncing and further blocks processing (the reaction
//! to block announcement from peers and the announcement of blocks produced by this node).

use chainstate::chainstate_interface::ChainstateInterface;
use utils::{atomics::AcqRelAtomicBool, sync::Arc};

#[derive(Clone)]
pub struct ChainstateHandle {
    handle: chainstate::ChainstateHandle,

    /// A cached result of the `ChainstateInterface::is_initial_block_download` call.
    is_initial_block_download: Arc<AcqRelAtomicBool>,
}

impl ChainstateHandle {
    pub fn new(handle: chainstate::ChainstateHandle) -> ChainstateHandle {
        ChainstateHandle {
            handle,
            is_initial_block_download: Arc::new(true.into()),
        }
    }

    pub async fn call_mut<R: Send + 'static>(
        &self,
        func: impl FnOnce(&mut dyn ChainstateInterface) -> crate::Result<R> + Send + 'static,
    ) -> crate::Result<R> {
        self.handle.call_mut(move |cs| func(cs)).await?
    }

    pub async fn call<R: Send + 'static>(
        &self,
        func: impl FnOnce(&dyn ChainstateInterface) -> crate::Result<R> + Send + 'static,
    ) -> crate::Result<R> {
        self.handle.call(move |cs| func(cs)).await?
    }

    pub async fn is_initial_block_download(&self) -> crate::Result<bool> {
        // Note: is_initial_block_download can only go from true to false.
        if !self.is_initial_block_download.load() {
            return Ok(false);
        }

        let new_val = self.handle.call(|cs| cs.is_initial_block_download()).await?;
        self.is_initial_block_download.store(new_val);
        Ok(new_val)
    }
}
