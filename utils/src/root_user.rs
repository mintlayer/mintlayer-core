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

use clap::Args;
use logging::log;

const FORCE_ALLOW_ROOT_FLAG: &str = "--force-allow-run-as-root";

#[derive(Args, Clone, Debug, Default)]
pub struct ForceRunAsRootOptions {
    /// Allow the program to be run as root, which is NOT RECOMMENDED and DANGEROUS.
    /// There is no need to run the mintlayer-software as root. The correct
    /// security practice is to only provide root access to programs that need it.
    #[clap(long, default_value_t = false)]
    pub force_allow_run_as_root: bool,
}

impl ForceRunAsRootOptions {
    pub fn ensure_not_running_as_root_user(&self) -> anyhow::Result<()> {
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
        ))]
        {
            if !self.force_allow_run_as_root {
                use std::os::unix::fs::MetadataExt;
                let uid = std::fs::metadata("/proc/self").map(|m| m.uid());
                match uid {
                    Ok(id) => {
                        if id == 0 {
                            return Err(anyhow::anyhow!("ERROR: It is a mistake to run as root (user with uid=0), as it gives the this software power that it does not need and violates good security practices. Either run the program as non-root, or do the VERY NOT RECOMMENDED THING TO DO, and add the flag `{FORCE_ALLOW_ROOT_FLAG}`"));
                        }
                    }
                    Err(e) => log::error!("Failed to get user id to prevent running as root: {e}"),
                }
            }
        }

        Ok(())
    }
}
