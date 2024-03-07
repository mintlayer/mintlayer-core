// Copyright (c) 2024 RBB S.r.l
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

use clap::Parser;

#[derive(Parser, Clone, Debug, Default)]
pub struct DocGenRunOptions {
    /// The path, to which the file will be written.
    /// If not specified, stdout will be used
    #[clap(long, short('o'), default_value = None)]
    pub output_file: Option<std::path::PathBuf>,

    /// The title of the documentation
    #[clap(long, short('t'))]
    pub doc_title: Option<String>,

    /// Whether to only check the target file without writing to an output file
    #[clap(long, short('c'))]
    pub check: bool,
}
