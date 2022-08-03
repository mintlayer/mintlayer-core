// Copyright (c) 2022 RBB S.r.l
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

use crate::{chain::block::timestamp::BlockTimestamp, primitives::BlockHeight};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Encode, Decode)]
pub enum OutputTimeLock {
    #[codec(index = 0)]
    UntilHeight(BlockHeight),
    #[codec(index = 1)]
    UntilTime(BlockTimestamp),
    #[codec(index = 2)]
    ForBlockCount(#[codec(compact)] u64),
    #[codec(index = 3)]
    ForSeconds(#[codec(compact)] u64),
}
