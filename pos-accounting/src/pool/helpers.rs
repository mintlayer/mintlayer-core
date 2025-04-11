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

use common::{
    chain::DelegationId,
    primitives::{Amount, H256},
};
use randomness::Rng;

use crate::{pool::operations::DelegateStakingUndo, PoSAccountingUndo};

pub fn random_undo_for_test(rng: &mut impl Rng) -> PoSAccountingUndo {
    let delegation_target: DelegationId = H256::random_using(rng).into();
    let amount_to_delegate = Amount::from_atoms(rng.gen_range(0..100_000));

    // TODO: return other undo types
    PoSAccountingUndo::DelegateStaking(DelegateStakingUndo {
        delegation_target,
        amount_to_delegate,
    })
}
