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

//! General framework for working with subsystems
//!
//! The [Manager] type handles a collection of subsystems. The framework also takes care of
//! inter-subsystem calls and clean shutdown. Subsystems communicate using [Handle]s.
//!
//! ## Calls
//!
//! Calls are dispatched by sending a closure over a channel to the subsystem. The subsystem then
//! sends the result back using a oneshot channel. The channel is awaited to emulate synchronous
//! calls.
//!
//! ## Shutdown sequence
//!
//! The shutdown proceeds in three phases:
//!
//! 1. As soon as any subsystem terminates, the main task is notified.
//! 2. The main task broadcasts the shutdown request to all subsystems. The subsystems react to the
//!    request by shutting themselves down.
//! 3. The main task waits for all subsystems to terminate.

pub mod manager;
pub mod subsystem;

pub use crate::manager::Manager;
pub use crate::subsystem::{CallRequest, CallResult, Handle, ShutdownRequest, Subsystem};
