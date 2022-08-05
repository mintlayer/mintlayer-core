// Copyright (c) 2022 RBB S.r.l
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

//! Regular concurrency primitives

// TODO we may want some of the following to come from tokio instead
pub use std::sync;
pub use std::thread;

pub mod concurrency {
    /// Regular concurrency model.
    ///
    /// Like `loom::model` but runs the body under normal concurrency primitives. Useful for
    /// writing tests that support both loom-based and normal execution.
    pub fn model<F: Fn() + Sync + Send + 'static>(body: F) {
        body()
    }
}
