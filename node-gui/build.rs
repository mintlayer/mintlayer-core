// Copyright (c) 2021-2023 RBB S.r.l
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
//

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::fs;
    use winres::WindowsResource;

    if !fs::metadata("app.manifest").is_ok() {
        return Err(format!("app.manifest not found in: {:?}", env::current_dir()?).into());
    }

    let mut res = WindowsResource::new();
    res.set_icon("../build-tools/assets/logo.ico");
    res.set_manifest_file("app.manifest");

    res.compile()?;

    println!("Resource compilation successful");
    Ok(())
}

#[cfg(not(windows))]
fn main() {}
