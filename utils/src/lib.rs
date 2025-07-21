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

pub mod array_2d;
pub mod atomics;
pub mod blockuntilzero;
pub mod bloom_filters;
pub mod clap_utils;
pub mod concatln;
pub mod config_setting;
pub mod const_nonzero;
pub mod const_value;
pub mod cookie;
pub mod counttracker;
pub mod cow_utils;
pub mod debug_panic;
pub mod default_data_dir;
pub mod displayable_option;
pub mod ensure;
pub mod env_utils;
pub mod eventhandler;
pub mod exp_rand;
pub mod graph_traversals;
pub mod log_utils;
pub mod maybe_encrypted;
pub mod newtype;
pub mod once_destructor;
pub mod qrcode;
pub mod root_user;
pub mod rust_backtrace;
pub mod set_flag;
pub mod shallow_clone;
pub mod sorted;
pub mod tap_log;
pub mod try_as;
pub mod workspace_path;

mod concurrency_impl;
pub use concurrency_impl::*;

pub use log_error::log_error;

// The internals of the `log_error` macro will refer to other parts of the repository as
// `utils::mintlayer_core_log_error_support::...`. The purpose of this is allow external projects
// to use `log_error` without polluting their namespaces with core-specific generic names.
pub mod mintlayer_core_log_error_support {
    pub use crate::log_utils::log;
    pub use logging::log::Level;

    // This is a 3rd-party crate that is used inside `log_error`.
    pub use fix_hidden_lifetime_bug;
}
