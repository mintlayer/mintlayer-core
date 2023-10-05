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

#![deny(clippy::clone_on_ref_ptr)]

pub use config::MempoolMaxSize;
pub use interface::{make_mempool, MempoolInterface, MempoolSubsystemInterface};
pub use mempool_types::{tx_origin, TxStatus};

mod config;
pub mod error;
pub mod event;
mod interface;
mod pool;
pub mod rpc;
pub mod tx_accumulator;

pub use pool::FeeRate;

pub type MempoolHandle = subsystem::Handle<dyn MempoolInterface>;

pub type Result<T> = core::result::Result<T, error::Error>;
