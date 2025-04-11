// Copyright (c) 2021-2025 RBB S.r.l
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

use super::{tokens::TokenId, DelegationId, OrderId, PoolId, TxInput, UtxoOutPoint};
use crate::primitives::id::{hash_encoded, hash_encoded_to, DefaultHashAlgoStream};

use crypto::hash::StreamHasher;

fn pool_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    0
}

fn delegation_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    1
}

pub fn make_pool_id(input0_outpoint: &UtxoOutPoint) -> PoolId {
    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut hasher);
    // 0 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(&pool_id_preimage_suffix(), &mut hasher);
    PoolId::new(hasher.finalize().into())
}

pub fn make_delegation_id(input0_outpoint: &UtxoOutPoint) -> DelegationId {
    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut hasher);
    // 1 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(&delegation_id_preimage_suffix(), &mut hasher);
    DelegationId::new(hasher.finalize().into())
}

pub fn make_order_id(input0_outpoint: &UtxoOutPoint) -> OrderId {
    OrderId::new(hash_encoded(input0_outpoint))
}

// TODO: the argument to the function should be a utxo, right now it might be an account
pub fn make_token_id(inputs: &[TxInput]) -> Option<TokenId> {
    Some(TokenId::new(hash_encoded(inputs.first()?)))
}
