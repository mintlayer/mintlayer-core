// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate_storage::Transactional;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        block::timestamp::BlockTimestamp, output_value::OutputValue, stakelock::StakePoolData,
        CoinUnit, Destination, Genesis, RequiredConsensus, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Compact, H256},
};
use consensus::ConsensusPoSError;
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::VRFPublicKey,
};
use randomness::{CryptoRng, Rng};

use super::block_index_handle_impl::TestBlockIndexHandle;

pub fn calculate_new_target(
    tf: &TestFramework,
    block_height: BlockHeight,
) -> Result<Compact, ConsensusPoSError> {
    let pos_status = match tf
        .chainstate
        .get_chain_config()
        .consensus_upgrades()
        .consensus_status(block_height)
    {
        RequiredConsensus::PoS(status) => status,
        RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
            panic!("Invalid consensus")
        }
    };

    let db_tx = tf.storage.transaction_ro().unwrap();
    let block_index_handle =
        TestBlockIndexHandle::new(db_tx, tf.chainstate.get_chain_config().as_ref());

    consensus::calculate_target_required(
        tf.chainstate.get_chain_config().as_ref(),
        &pos_status,
        tf.best_block_id(),
        &block_index_handle,
    )
}

// Alongside `StakePoolData` also returns `PrivateKey` that allows to sign a block that spends a kernel
// with this pool data
pub fn create_stake_pool_data_with_all_reward_to_staker(
    rng: &mut (impl Rng + CryptoRng),
    amount: Amount,
    vrf_pk: VRFPublicKey,
) -> (StakePoolData, PrivateKey) {
    let (sk, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

    (
        StakePoolData::new(
            amount,
            Destination::PublicKey(pk),
            vrf_pk,
            Destination::AnyoneCanSpend,
            PerThousand::new(1000).unwrap(), // give all reward to the staker
            Amount::ZERO,
        ),
        sk,
    )
}

pub fn create_custom_genesis_with_stake_pool(
    staker_pk: PublicKey,
    vrf_pk: VRFPublicKey,
) -> Genesis {
    let initial_amount = CoinUnit::from_coins(100_000_000).to_amount_atoms();
    let initial_pool_amount = (initial_amount / 3).unwrap();
    let initial_mint_amount = (initial_amount - initial_pool_amount).unwrap();

    create_custom_genesis_with_stake_pool_specify_amounts(
        staker_pk,
        vrf_pk,
        initial_mint_amount,
        initial_pool_amount,
    )
}

pub fn create_custom_genesis_with_stake_pool_specify_amounts(
    staker_pk: PublicKey,
    vrf_pk: VRFPublicKey,
    initial_mint_amount: Amount,
    initial_pool_amount: Amount,
) -> Genesis {
    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(initial_mint_amount),
        Destination::AnyoneCanSpend,
    );

    let initial_pool = TxOutput::CreateStakePool(
        H256::zero().into(),
        Box::new(StakePoolData::new(
            initial_pool_amount,
            Destination::PublicKey(staker_pk.clone()),
            vrf_pk,
            Destination::PublicKey(staker_pk),
            PerThousand::new(10).expect("Per thousand should be valid"),
            Amount::from_atoms(100),
        )),
    );

    Genesis::new(
        "Genesis message".to_string(),
        BlockTimestamp::from_int_seconds(1685025323),
        vec![mint_output, initial_pool],
    )
}
