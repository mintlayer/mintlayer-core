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

use clap::Arg;
use heck::ToShoutySnakeCase;

/// This function can be used with clap's `mut_args` to add the "env" attribute
/// to each field of a struct that derives `clap::Parser`.
///
/// The name of the environment variable will be based on the "long" name of the argument;
/// if the argument has no long name, "env" won't be set. E.g.
/// ```
/// # use utils::clap_utils::add_env;
/// #[derive(clap::Parser)]
/// #[clap(mut_args(|arg| add_env("FOO", arg)))]
/// pub struct MyOptions {
///     #[arg(long)]
///     pub the_option_name: String,
/// }
/// ```
/// In this example, the env var name will be `ML_FOO_THE_OPTION_NAME`.
///
/// By convention, the infix ("FOO" in the example above) is supposed to uniquely identify
/// the executable for which the arguments are being defined.
pub fn add_env(infix: &str, mut arg: Arg) -> Arg {
    if let Some(long_name) = arg.get_long() {
        let var_name = format!("ML_{}_{}", infix, long_name.to_shouty_snake_case());
        arg = arg.env(var_name);
    }

    arg
}

/// A convenience function to make the corresponding calls to `mut_args` less noisy.
pub fn env_adder(infix: &str) -> impl FnMut(Arg) -> Arg + '_ {
    |arg| add_env(infix, arg)
}
