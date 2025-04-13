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
    primitives::{per_thousand::PerThousand, Amount, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::{CryptoRng, Rng};

use crate::{
    error::Error, storage::in_memory::InMemoryPoSAccounting, DelegationData,
    PoSAccountingOperations, PoSAccountingUndo, PoolData,
};

mod delta_tests;
mod operations_tests;
mod simulation_tests;
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

fn create_pool_data(
    rng: &mut (impl Rng + CryptoRng),
    decommission_destination: Destination,
    pledged_amount: Amount,
) -> PoolData {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let margin_ratio = PerThousand::new(rng.gen_range(0..1000)).unwrap();
    let cost_per_block = Amount::from_atoms(rng.gen_range(0..1000));
    PoolData::new(
        decommission_destination,
        pledged_amount,
        Amount::ZERO,
        vrf_pk,
        margin_ratio,
        cost_per_block,
    )
}

fn create_pool(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut impl PoSAccountingOperations<PoSAccountingUndo>,
    pledged_amount: Amount,
) -> Result<(PoolId, PoolData, PoSAccountingUndo), Error> {
    let destination = new_pub_key_destination(rng);
    let pool_data = create_pool_data(rng, destination, pledged_amount);
    let pool_id = PoolId::random_using(rng);
    op.create_pool(pool_id, pool_data.clone())
        .map(|undo| (pool_id, pool_data, undo))
}

fn create_delegation_id(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut impl PoSAccountingOperations<PoSAccountingUndo>,
    target_pool: PoolId,
) -> Result<(DelegationId, Destination, PoSAccountingUndo), Error> {
    let destination = new_pub_key_destination(rng);
    let delegation_id = DelegationId::random_using(rng);
    op.create_delegation_id(target_pool, delegation_id, destination.clone())
        .map(|undo| (delegation_id, destination, undo))
}

fn create_storage_with_pool(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
) -> (PoolId, PoolData, InMemoryPoSAccounting) {
    let pool_id = new_pool_id(rng.next_u64());
    let destination = new_pub_key_destination(rng);
    let pool_data = create_pool_data(rng, destination, pledged_amount);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data.clone())]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    (pool_id, pool_data, storage)
}

fn create_storage_with_pool_and_delegation(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
    delegated_amount: Amount,
) -> (
    PoolId,
    PoolData,
    DelegationId,
    Destination,
    InMemoryPoSAccounting,
) {
    let pool_id = new_pool_id(rng.next_u64());
    let destination_pool = new_pub_key_destination(rng);
    let delegation_id = new_delegation_id(rng.next_u64());
    let destination_del = new_pub_key_destination(rng);
    let pool_data = create_pool_data(rng, destination_pool, pledged_amount);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data.clone())]),
        BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
        BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
        BTreeMap::from([(delegation_id, delegated_amount)]),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, destination_del.clone()),
        )]),
    );
    (pool_id, pool_data, delegation_id, destination_del, storage)
}
