// Copyright (c) 2022-2023 RBB S.r.l
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

/// Defines hooks into a subsystem lifecycle.
#[async_trait::async_trait]
pub trait Subsystem: Send + Sync + Sized + 'static {
    type Interface: ?Sized + Send + Sync;

    /// Get the call interface (immutable version)
    fn interface_ref(&self) -> &Self::Interface;

    /// Get the call interface (mutable version)
    fn interface_mut(&mut self) -> &mut Self::Interface;

    /// Perform a unit of background work. Background work is scheduled if the subsystem has
    /// nothing else to do. A unit of background work should not take too much time.
    fn perform_background_work_unit(&mut self) {}

    /// Check if the subsystem has background work to do.
    fn has_background_work(&self) -> bool {
        false
    }

    /// Custom shutdown procedure.
    async fn shutdown(self) {}
}
