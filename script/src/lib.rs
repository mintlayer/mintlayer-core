// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek

//! This library provides scripting capabilities targeting blockchain applications largely
//! compatible with Bitcoin script. Most opcodes have semantics identical to Bitcoin script,
//! however the library also provides a number of customization points to allow the user to
//! deviate from, extend and customize the capabilities of the scripting engine. Most notably,
//! signatures can be fully customized. For more info, see the [Context] trait.
//!
//! ## Example
//!
//! Here is how to create a simple script and run it using [TestContext]:
//!
//! ```
//! use script::{Builder, Stack, TestContext, run_script};
//! use script::opcodes::all as opc;
//!
//! // Build a script that calculates 3 + 5.
//! let script = Builder::new()
//!         .push_int(3)
//!         .push_int(5)
//!         .push_opcode(opc::OP_ADD)
//!         .into_script();
//!
//! // Set up stack and context, run the interpreter.
//! let stack = Stack::default();
//! let ctx = TestContext::new("TRANSACTION DATA HERE".as_bytes().to_owned());
//! let result = run_script(&ctx, &script, stack);
//!
//! // Check if the final stack result is [0x08].
//! let mut expected = Stack::from(vec![vec![0x08].into()]);
//! assert_eq!(result, Ok(expected));
//! ```

#[macro_use]
mod util;

pub mod context;
mod error;
mod interpreter;
pub mod opcodes;
pub mod script;
pub mod sighash;
#[cfg(all(test, not(loom)))]
mod test;

#[cfg(feature = "testcontext")]
pub use context::testcontext::TestContext;
pub use context::Context;
pub use error::{Error, Result};
pub use interpreter::{run_pushdata, run_script, verify_witness_lock, Stack};
pub use crate::script::{Builder, Script};
