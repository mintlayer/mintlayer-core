// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! An abstraction over concurrency primitives
//!
//! This exists mainly to support permutation testing with loom. If loom is enabled, concurrency
//! primitives from loom are exported. Otherwise, standard concurrency primitives are used.

#[cfg(loom)]
#[path = "loom.rs"]
mod this;

#[cfg(not(loom))]
#[path = "regular.rs"]
mod this;

pub use this::*;
