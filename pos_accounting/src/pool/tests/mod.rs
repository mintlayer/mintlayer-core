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

use common::{
    chain::{DelegationId, Destination, PoolId},
    primitives::{Amount, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::{CryptoRng, Rng},
};

use crate::{storage::in_memory::InMemoryPoSAccounting, DelegationData, PoolData};

mod delta_tests;
mod operations_tests;
mod undo_tests;

fn new_pool_id(v: u64) -> PoolId {
    PoolId::new(H256::from_low_u64_be(v))
}

fn new_delegation_id(v: u64) -> DelegationId {
    DelegationId::new(H256::from_low_u64_be(v))
}

fn new_pub_key_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pub_key)
}

fn create_storage_with_pool(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
) -> (PoolId, Destination, InMemoryPoSAccounting) {
    let pool_id = new_pool_id(rng.next_u64());
    let destination = new_pub_key_destination(rng);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(destination.clone(), pledged_amount))]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    (pool_id, destination, storage)
}

fn create_storage_with_pool_and_delegation(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
    delegated_amount: Amount,
) -> (
    PoolId,
    Destination,
    DelegationId,
    Destination,
    InMemoryPoSAccounting,
) {
    let pool_id = new_pool_id(rng.next_u64());
    let destination_pool = new_pub_key_destination(rng);
    let delegation_id = new_delegation_id(rng.next_u64());
    let destination_del = new_pub_key_destination(rng);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(
            pool_id,
            PoolData::new(destination_pool.clone(), pledged_amount),
        )]),
        BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
        BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
        BTreeMap::from([(delegation_id, delegated_amount)]),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, destination_del.clone()),
        )]),
    );
    (
        pool_id,
        destination_pool,
        delegation_id,
        destination_del,
        storage,
    )
}
