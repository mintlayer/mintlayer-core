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
// Author(s): S. Afach

use serialization::{Decode, Encode};

use super::schnorrkel::data::SchnorrkelVRFReturn;

#[must_use]
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub enum VRFReturn {
    Schnorrkel(SchnorrkelVRFReturn),
}

impl From<SchnorrkelVRFReturn> for VRFReturn {
    fn from(r: SchnorrkelVRFReturn) -> Self {
        VRFReturn::Schnorrkel(r)
    }
}
