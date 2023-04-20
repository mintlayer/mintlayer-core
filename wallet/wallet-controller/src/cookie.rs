// Copyright (c) 2023 RBB S.r.l
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

use std::path::Path;

// TODO: Replace String with custom error
pub fn load_cookie(path: impl AsRef<Path>) -> Result<(String, String), String> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    let (username, password) = content.split_once(':').ok_or(format!(
        "Invalid cookie file {:?}: ':' not found",
        path.as_ref()
    ))?;
    Ok((username.to_owned(), password.to_owned()))
}
