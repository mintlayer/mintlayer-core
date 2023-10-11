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

use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{CryptoRng, Rng};

use super::*;
use crate::chain::block::timestamp::BlockTimestamp;
use crate::chain::output_value::OutputValue;
use crate::chain::signature::inputsig::standard_signature::StandardInputSignature;
use crate::chain::signed_transaction::SignedTransaction;
use crate::{
    chain::{
        block::{BlockReward, ConsensusData},
        signature::{inputsig::InputWitness, sighash::sighashtype::SigHashType},
        Destination, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, H256},
};
use rstest::rstest;
use std::str::FromStr;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

#[test]
fn invalid_output_count_for_transaction() {
    let block_id =
        H256::from_str("000000000000000000000000000000000000000000000000000000000000007b").unwrap();
    let pos = TxMainChainPosition::new(block_id.into(), 1).into();
    let tx_index = TxMainChainIndex::new(pos, 0);
    assert_eq!(
        tx_index.unwrap_err(),
        TxMainChainIndexError::InvalidOutputCount
    );
}

#[test]
fn invalid_output_count_ok_for_block_reward() {
    let block_id =
        H256::from_str("000000000000000000000000000000000000000000000000000000000000007b").unwrap();
    let pos: Id<Block> = block_id.into();
    let tx_index = TxMainChainIndex::new(pos.into(), 0);
    tx_index.unwrap();
}

#[test]
fn basic_spending() {
    let block_id: Id<Block> =
        H256::from_str("000000000000000000000000000000000000000000000000000000000000007b")
            .unwrap()
            .into();
    let pos = TxMainChainPosition::new(block_id, 1).into();
    let mut tx_index = TxMainChainIndex::new(pos, 3).unwrap();

    // ensure index accesses are correct
    assert!(tx_index.get_spent_state(0).is_ok());
    assert!(tx_index.get_spent_state(1).is_ok());
    assert!(tx_index.get_spent_state(2).is_ok());
    assert_eq!(
        tx_index.get_spent_state(3).unwrap_err(),
        SpendError::OutOfRange {
            tx_id: None,
            source_output_index: 3
        }
    );
    assert_eq!(
        tx_index.get_spent_state(4).unwrap_err(),
        SpendError::OutOfRange {
            tx_id: None,
            source_output_index: 4
        }
    );
    assert_eq!(tx_index.output_count(), 3);

    let p = match tx_index.position {
        SpendablePosition::Transaction(ref p) => p,
        _ => {
            unreachable!();
        }
    };

    // check that all are unspent
    assert_eq!(
        p.block_id,
        Into::<Id<Block>>::into(H256::from_low_u64_be(123))
    );
    for output in &tx_index.spent {
        assert_eq!(*output, OutputSpentState::Unspent);
    }
    assert!(!tx_index.all_outputs_spent());

    for i in 0..tx_index.output_count() {
        assert_eq!(
            tx_index.get_spent_state(i).unwrap(),
            OutputSpentState::Unspent
        );
    }

    let tx_spending_output_0 = Id::<Transaction>::new(
        H256::from_str("0000000000000000000000000000000000000000000000000000000000000333").unwrap(),
    );
    let tx_spending_output_1 = Id::<Block>::new(
        H256::from_str("0000000000000000000000000000000000000000000000000000000000000444").unwrap(),
    );
    let tx_spending_output_2 = Id::<Transaction>::new(
        H256::from_str("0000000000000000000000000000000000000000000000000000000000000555").unwrap(),
    );

    // spend one output
    let spend_0_res = tx_index.spend(0, tx_spending_output_0.into());
    assert!(spend_0_res.is_ok());

    // check state
    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_0.into())
    );
    assert_eq!(
        tx_index.get_spent_state(1).unwrap(),
        OutputSpentState::Unspent
    );
    assert_eq!(
        tx_index.get_spent_state(2).unwrap(),
        OutputSpentState::Unspent
    );

    assert!(!tx_index.all_outputs_spent());

    // attempt double-spend
    assert_eq!(
        tx_index.spend(0, tx_spending_output_1.into()).unwrap_err(),
        SpendError::AlreadySpent(tx_spending_output_0.into())
    );

    // spend all other outputs
    assert!(tx_index.spend(1, tx_spending_output_1.into()).is_ok());
    assert!(tx_index.spend(2, tx_spending_output_2.into()).is_ok());

    // check that all are spent
    assert!(tx_index.all_outputs_spent());

    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_0.into())
    );
    assert_eq!(
        tx_index.get_spent_state(1).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_1.into())
    );
    assert_eq!(
        tx_index.get_spent_state(2).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_2.into())
    );

    // unspend output 1
    assert!(tx_index.unspend(0).is_ok());

    // cannot "double unspend"
    assert_eq!(tx_index.unspend(0).unwrap_err(), SpendError::AlreadyUnspent);

    // check the new unspent state
    assert!(!tx_index.all_outputs_spent());
    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::Unspent
    );
    assert_eq!(
        tx_index.get_spent_state(1).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_1.into())
    );
    assert_eq!(
        tx_index.get_spent_state(2).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_2.into())
    );

    // unspent the rest
    assert!(tx_index.unspend(1).is_ok());
    assert!(tx_index.unspend(2).is_ok());

    // check the new unspent state
    assert!(!tx_index.all_outputs_spent());
    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::Unspent
    );
    assert_eq!(
        tx_index.get_spent_state(1).unwrap(),
        OutputSpentState::Unspent
    );
    assert_eq!(
        tx_index.get_spent_state(2).unwrap(),
        OutputSpentState::Unspent
    );
}

fn generate_random_h256(rng: &mut impl Rng) -> H256 {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    H256::from(bytes)
}

fn generate_random_bytes(rng: &mut impl Rng, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn generate_random_invalid_witness(count: usize, rng: &mut impl Rng) -> Vec<InputWitness> {
    (0..count)
        .map(|_| {
            let witness_size = rng.next_u32();
            let witness_size = 1 + witness_size % 1000;
            let witness = generate_random_bytes(rng, witness_size as usize);
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                witness,
            ))
        })
        .collect::<Vec<_>>()
}

fn generate_random_invalid_input(rng: &mut impl Rng) -> TxInput {
    let outpoint = if rng.next_u32() % 2 == 0 {
        OutPointSourceId::Transaction(Id::new(generate_random_h256(rng)))
    } else {
        OutPointSourceId::BlockReward(Id::new(generate_random_h256(rng)))
    };

    TxInput::from_utxo(outpoint, rng.next_u32())
}

fn generate_random_invalid_output(rng: &mut (impl Rng + CryptoRng)) -> TxOutput {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(rng.next_u64() as u128)),
        Destination::PublicKey(pub_key),
    )
}

fn generate_random_invalid_transaction(rng: &mut (impl Rng + CryptoRng)) -> Transaction {
    let inputs = {
        let input_count = 1 + (rng.next_u32() as usize) % 10;
        (0..input_count).map(|_| generate_random_invalid_input(rng)).collect::<Vec<_>>()
    };

    let outputs = {
        let output_count = 1 + (rng.next_u32() as usize) % 10;
        (0..output_count)
            .map(|_| generate_random_invalid_output(rng))
            .collect::<Vec<_>>()
    };

    let flags = rng.gen::<u128>();

    Transaction::new(flags, inputs, outputs).expect("Creating tx caused fail")
}

fn generate_random_invalid_block(rng: &mut (impl Rng + CryptoRng)) -> Block {
    let transactions = {
        let transaction_count = rng.next_u32() % 20;
        (0..transaction_count)
            .map(|_| generate_random_invalid_transaction(rng))
            .collect::<Vec<_>>()
    };
    let transactions = transactions
        .into_iter()
        .map(|tx| {
            let inputs_count = tx.inputs().len();
            SignedTransaction::new(tx, generate_random_invalid_witness(inputs_count, rng))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid witness count");
    let time = rng.next_u64();
    let prev_id = Id::new(generate_random_h256(rng));
    let reward = BlockReward::new(Vec::new());

    Block::new(
        transactions,
        prev_id,
        BlockTimestamp::from_int_seconds(time),
        ConsensusData::None,
        reward,
    )
    .expect("Creating block caused fail")
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_indices_calculations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let block = generate_random_invalid_block(&mut rng);

    let tested = || ();

    match &block {
        Block::V1(_) => tested(),
        // If this is triggering an error, that means you have to add a test for the new Block version; don't ignore it!
    };

    let serialized_block = block.encode();
    let serialized_header = block.header().encode();
    let serialized_transactions = block.transactions().encode();
    let serialized_reward = block.block_reward().encode();
    assert_eq!(
        // no need to add enum arm byte, the version is already a part of the header data
        serialized_header.len() + serialized_transactions.len() + serialized_reward.len(),
        serialized_block.len(),
    );

    let tx_offsets = calculate_tx_offsets_in_block(&block).unwrap();
    assert_eq!(tx_offsets.len(), block.transactions().len());

    for (tx, tx_index) in block.transactions().iter().zip(tx_offsets.iter()) {
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(tx_index.output_count(), tx.outputs().len() as u32);

        let pos = match tx_index.position() {
            SpendablePosition::Transaction(pos) => pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        let tx_start_pos = pos.byte_offset_in_block() as usize;
        let tx_serialized_in_block = &serialized_block[tx_start_pos..];
        let tx_serialized = tx.encode();
        assert_eq!(tx_serialized_in_block[..tx_serialized.len()], tx_serialized);

        // to ensure Vec comparison is correct since I'm a paranoid C++ dude, let's mess things up
        let tx_messed = tx_serialized.iter().map(|c| c.wrapping_add(1)).collect::<Vec<u8>>();
        assert_ne!(tx_serialized_in_block, tx_messed);
    }
}
