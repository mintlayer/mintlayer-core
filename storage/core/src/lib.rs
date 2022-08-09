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

//! Core backend-agnostic storage abstractions

pub mod error;
pub mod schema;
pub mod traits;
pub mod transaction;

// Reexport items from the temporary basic implementation.
pub use error::Error;
pub use transaction::{abort, commit};

pub type Data = Vec<u8>;
pub type Result<T> = std::result::Result<T, Error>;
