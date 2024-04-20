// Copyright (c) 2023 RBB S.r.l
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

use chainstate_test_framework::empty_witness;
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        output_value::OutputValue, stakelock::StakePoolData, Block, DelegationId, Destination,
        OutPointSourceId, PoolId, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::{CryptoRng, Rng};

pub fn prepare_stake_pool(
    stake_pool_outpoint: UtxoOutPoint,
    rng: &mut (impl Rng + CryptoRng),
    available_amount: &mut Amount,
    tf: &mut TestFramework,
) -> (UtxoOutPoint, StakePoolData, PoolId, Block) {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let min_stake_pool_pledge =
        tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
    let amount_to_stake =
        Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 2)));

    let (_, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    let margin_ratio_per_thousand = rng.gen_range(1..=1000);
    let stake_pool_data = StakePoolData::new(
        amount_to_stake,
        Destination::PublicKey(pk),
        vrf_pk,
        Destination::PublicKeyHash(PublicKeyHash::from_low_u64_ne(rng.gen::<u64>())),
        PerThousand::new(margin_ratio_per_thousand).unwrap(),
        Amount::ZERO,
    );
    let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);

    *available_amount = (*available_amount - amount_to_stake).unwrap();
    let stake_pool_transaction = TransactionBuilder::new()
        .add_input(stake_pool_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data.clone()),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(*available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(stake_pool_transaction.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(stake_pool_transaction).build();

    (transfer_outpoint, stake_pool_data, pool_id, block)
}

pub fn prepare_delegation(
    transfer_outpoint: UtxoOutPoint,
    rng: &mut (impl Rng + CryptoRng),
    pool_id: PoolId,
    available_amount: Amount,
    destination: Option<Destination>,
    tf: &mut TestFramework,
) -> (DelegationId, Destination, UtxoOutPoint, Block) {
    let delegation_id = pos_accounting::make_delegation_id(&transfer_outpoint);
    let (_, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let destination = destination.unwrap_or(Destination::PublicKey(pk));
    let create_delegation_tx = TransactionBuilder::new()
        .add_input(transfer_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateDelegationId(destination.clone(), pool_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(available_amount),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(create_delegation_tx.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(create_delegation_tx).build();

    (delegation_id, destination, transfer_outpoint, block)
}

pub fn stake_delegation(
    rng: &mut impl Rng,
    available_amount: Amount,
    transfer_outpoint: UtxoOutPoint,
    delegation_id: DelegationId,
    tf: &mut TestFramework,
) -> (Amount, UtxoOutPoint, Block) {
    let delegate_max_amount = std::cmp::min(1000, available_amount.into_atoms());
    let amount_to_delegate = Amount::from_atoms(rng.gen_range(1..=delegate_max_amount));
    let stake_tx = TransactionBuilder::new()
        .add_input(transfer_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((available_amount - amount_to_delegate).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(stake_tx.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(stake_tx).build();

    (amount_to_delegate, transfer_outpoint, block)
}
