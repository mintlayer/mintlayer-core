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

use chainstate_test_framework::{empty_witness, TestFramework, TransactionBuilder};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        make_delegation_id, make_token_id,
        output_value::OutputValue,
        stakelock::StakePoolData,
        tokens::{TokenId, TokenIssuance, TokenTotalSupply},
        AccountCommand, AccountNonce, Block, DelegationId, Destination, OutPointSourceId, PoolId,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Idable},
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
    let pool_id = PoolId::from_utxo(&stake_pool_outpoint);

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

    let block = tf.make_block_builder().add_transaction(stake_pool_transaction).build(rng);
    tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap();

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
    let delegation_id = make_delegation_id(create_delegation_tx.inputs()).unwrap();

    let transfer_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(create_delegation_tx.transaction().get_id()),
        1,
    );

    let block = tf.make_block_builder().add_transaction(create_delegation_tx).build(rng);
    tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap();

    (delegation_id, destination, transfer_outpoint, block)
}

pub fn stake_delegation(
    rng: &mut (impl Rng + CryptoRng),
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

    let block = tf.make_block_builder().add_transaction(stake_tx).build(rng);
    tf.process_block(block.clone(), chainstate::BlockSource::Local).unwrap();

    (amount_to_delegate, transfer_outpoint, block)
}

pub struct IssueAndMintTokensResult {
    pub token_id: TokenId,

    pub issue_block: Block,
    pub mint_block: Block,

    pub change_outpoint: UtxoOutPoint,
    pub tokens_outpoint: UtxoOutPoint,
}

pub fn issue_and_mint_tokens_from_genesis(
    min_mint_amount: Amount,
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> IssueAndMintTokensResult {
    let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

    let min_mint_amount_atoms = min_mint_amount.into_atoms();
    let issuance = test_utils::token_utils::random_token_issuance_v1_with_min_supply(
        tf.chain_config(),
        Destination::AnyoneCanSpend,
        min_mint_amount_atoms,
        rng,
    );
    let amount_to_mint = match issuance.total_supply {
        TokenTotalSupply::Fixed(limit) => {
            Amount::from_atoms(rng.gen_range(min_mint_amount_atoms..=limit.into_atoms()))
        }
        TokenTotalSupply::Lockable | TokenTotalSupply::Unlimited => {
            Amount::from_atoms(rng.gen_range(min_mint_amount_atoms..min_mint_amount_atoms * 10))
        }
    };

    let genesis_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 0);
    let genesis_coins = chainstate_test_framework::get_output_value(
        tf.chainstate.utxo(&genesis_outpoint).unwrap().unwrap().output(),
    )
    .unwrap()
    .coin_amount()
    .unwrap();
    let coins_after_issue = (genesis_coins - token_issuance_fee).unwrap();

    // Issue token
    let tx1 = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_after_issue),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
            issuance,
        ))))
        .build();
    let token_id = make_token_id(
        tf.chain_config(),
        tf.next_block_height(),
        tx1.transaction().inputs(),
    )
    .unwrap();
    let tx1_id = tx1.transaction().get_id();
    let block1 = tf.make_block_builder().add_transaction(tx1).build(rng);

    tf.process_block(block1.clone(), chainstate::BlockSource::Local).unwrap();

    // Mint tokens
    let token_supply_change_fee =
        tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());
    let coins_after_mint = (coins_after_issue - token_supply_change_fee).unwrap();

    let tx2 = TransactionBuilder::new()
        .add_input(
            TxInput::from_command(
                AccountNonce::new(0),
                AccountCommand::MintTokens(token_id, amount_to_mint),
            ),
            empty_witness(rng),
        )
        .add_input(TxInput::from_utxo(tx1_id.into(), 0), empty_witness(rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_after_mint),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, amount_to_mint),
            Destination::AnyoneCanSpend,
        ))
        .build();

    let tx2_id = tx2.transaction().get_id();
    let block2 = tf.make_block_builder().add_transaction(tx2).build(rng);

    tf.process_block(block2.clone(), chainstate::BlockSource::Local).unwrap();

    IssueAndMintTokensResult {
        token_id,
        issue_block: block1,
        mint_block: block2,
        change_outpoint: UtxoOutPoint::new(tx2_id.into(), 0),
        tokens_outpoint: UtxoOutPoint::new(tx2_id.into(), 1),
    }
}
