// Copyright (c) 2021-2024 RBB S.r.l
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

//! Here we have various types intended to represent trees of items that already have a parent-child
//! relationship (such as blocks or block-like structs, like chainstate's `BlockIndex`).

pub mod primitives;
pub mod tree_wrappers;

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    #[error(transparent)]
    PrimitivesError(#[from] primitives::Error),
    #[error(transparent)]
    TreeWrappersError(#[from] tree_wrappers::Error),
}
