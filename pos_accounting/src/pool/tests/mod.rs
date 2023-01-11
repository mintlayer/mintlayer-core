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

use std::collections::BTreeMap;

use common::primitives::{Amount, H256};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    random::{CryptoRng, Rng},
};

use crate::{
    storage::in_memory::InMemoryPoSAccounting, DelegationData, DelegationId, PoolData, PoolId,
};

mod delta_tests;
mod operations_tests;
mod undo_tests;

fn new_pool_id(v: u64) -> PoolId {
    PoolId::new(H256::from_low_u64_be(v))
}

fn new_delegation_id(v: u64) -> DelegationId {
    DelegationId::new(H256::from_low_u64_be(v))
}

fn create_storage_with_pool(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
) -> (PoolId, PublicKey, InMemoryPoSAccounting) {
    let pool_id = new_pool_id(rng.next_u64());
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(pub_key.clone(), pledged_amount))]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    (pool_id, pub_key, storage)
}

fn create_storage_with_pool_and_delegation(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
    delegated_amount: Amount,
) -> (
    PoolId,
    PublicKey,
    DelegationId,
    PublicKey,
    InMemoryPoSAccounting,
) {
    let pool_id = new_pool_id(rng.next_u64());
    let delegation_id = new_delegation_id(rng.next_u64());
    let (_, pub_key_pool) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);
    let (_, pub_key_del) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(pub_key_pool.clone(), pledged_amount))]),
        BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
        BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
        BTreeMap::from([(delegation_id, delegated_amount)]),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, pub_key_del.clone()),
        )]),
    );
    (pool_id, pub_key_pool, delegation_id, pub_key_del, storage)
}
