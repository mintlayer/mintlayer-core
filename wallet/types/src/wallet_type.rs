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

use serde::{Deserialize, Serialize};
use serialization::{Decode, Encode};
use std::fmt::{Display, Formatter};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub enum WalletType {
    #[codec(index = 0)]
    Cold,
    #[codec(index = 1)]
    Hot,
}

impl Display for WalletType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hot => write!(f, "Hot"),
            Self::Cold => write!(f, "Cold"),
        }
    }
}

impl WalletType {
    pub fn from_str(input: &str) -> Result<Self, String> {
        match input.to_lowercase().as_str() {
            "cold" => Ok(WalletType::Cold),
            "hot" => Ok(WalletType::Hot),
            _ => Err(format!("Invalid wallet type: {}", input)),
        }
    }
}
