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

use common::primitives::H256;

use crate::{DelegationId, PoolId};

mod delta_tests;
mod operations_tests;
mod undo_tests;

fn new_pool_id(v: u64) -> PoolId {
    PoolId::new(H256::from_low_u64_be(v))
}

fn new_delegation_id(v: u64) -> DelegationId {
    DelegationId::new(H256::from_low_u64_be(v))
}
