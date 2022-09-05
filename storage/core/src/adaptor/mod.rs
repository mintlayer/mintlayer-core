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

//! A number of tools to compose backends from smaller components

mod locking;

pub use locking::Locking;

use crate::backend;

/// Storage constructor abstraction
pub trait Construct: Sized {
    /// Type the storage can be initialized from
    type From;

    /// Construct storage from the initializer and database description
    fn construct(init: Self::From, desc: crate::info::DbDesc) -> crate::Result<Self>;
}

/// Core operations on storage without transaction support
pub trait CoreOps: backend::ReadOps + backend::WriteOps + Construct {}
// CoreOps is automatically implemented if pre-requisits are satisfied
impl<T: backend::ReadOps + backend::WriteOps + Construct> CoreOps for T {}
