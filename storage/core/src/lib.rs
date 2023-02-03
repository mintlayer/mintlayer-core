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

//! Definitions used to implement storage backends

pub mod adaptor;
pub mod backend;
pub mod error;
pub mod info;
pub mod util;

// Re-export some commonly used items
pub use backend::Backend;
pub use error::Error;
pub use info::{DbDesc, DbMapCount, DbMapDesc, DbMapId, DbMapsData};

/// Raw byte sequences, used to represent store keys and values
pub type Data = Vec<u8>;

/// A `Result` type specialized for storage
pub type Result<T> = std::result::Result<T, Error>;
