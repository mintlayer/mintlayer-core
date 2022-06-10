use crypto::key::{KeyKind, PrivateKey};
use crypto::random::RngCore;

use super::*;
use crate::{
    chain::{
        block::ConsensusData,
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype::SigHashType,
        },
        Destination, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, H256},
};
use std::str::FromStr;

#[test]
fn invalid_output_count_for_transaction() {
    let block_id =
        H256::from_str("000000000000000000000000000000000000000000000000000000000000007b").unwrap();
    let pos = TxMainChainPosition::new(block_id.into(), 1, 2).into();
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
    let pos = TxMainChainPosition::new(block_id, 1, 2).into();
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
    assert_eq!(tx_index.get_output_count(), 3);

    let p = match tx_index.position {
        SpendablePosition::Transaction(ref p) => p,
        _ => {
            unreachable!();
        }
    };

    // check that all are unspent
    assert_eq!(p.block_id, H256::from_low_u64_be(123).into());
    for output in &tx_index.spent {
        assert_eq!(*output, OutputSpentState::Unspent);
    }
    assert!(!tx_index.all_outputs_spent());

    for i in 0..tx_index.get_output_count() {
        assert_eq!(
            tx_index.get_spent_state(i).unwrap(),
            OutputSpentState::Unspent
        );
    }

    let tx_spending_output_0 = Id::<Transaction>::new(
        &H256::from_str("0000000000000000000000000000000000000000000000000000000000000333")
            .unwrap(),
    );
    let tx_spending_output_1 = Id::<Block>::new(
        &H256::from_str("0000000000000000000000000000000000000000000000000000000000000444")
            .unwrap(),
    );
    let tx_spending_output_2 = Id::<Transaction>::new(
        &H256::from_str("0000000000000000000000000000000000000000000000000000000000000555")
            .unwrap(),
    );

    // spend one output
    let spend_0_res = tx_index.spend(0, tx_spending_output_0.clone().into());
    assert!(spend_0_res.is_ok());

    // check state
    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_0.clone().into())
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
        tx_index.spend(0, tx_spending_output_1.clone().into()).unwrap_err(),
        SpendError::AlreadySpent(tx_spending_output_0.clone().into())
    );

    // spend all other outputs
    assert!(tx_index.spend(1, tx_spending_output_1.clone().into()).is_ok());
    assert!(tx_index.spend(2, tx_spending_output_2.clone().into()).is_ok());

    // check that all are spent
    assert!(tx_index.all_outputs_spent());

    assert_eq!(
        tx_index.get_spent_state(0).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_0.into())
    );
    assert_eq!(
        tx_index.get_spent_state(1).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_1.clone().into())
    );
    assert_eq!(
        tx_index.get_spent_state(2).unwrap(),
        OutputSpentState::SpentBy(tx_spending_output_2.clone().into())
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

fn generate_random_h256(g: &mut impl crypto::random::Rng) -> H256 {
    let mut bytes = [0u8; 32];
    g.fill_bytes(&mut bytes);
    H256::from(bytes)
}

fn generate_random_bytes(g: &mut impl crypto::random::Rng, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.resize(length, 0);
    g.fill_bytes(&mut bytes);
    bytes
}

fn generate_random_invalid_input(g: &mut impl crypto::random::Rng) -> TxInput {
    let witness_size = g.next_u32();
    let witness = generate_random_bytes(g, (1 + witness_size % 1000) as usize);
    let outpoint = if g.next_u32() % 2 == 0 {
        OutPointSourceId::Transaction(Id::new(&generate_random_h256(g)))
    } else {
        OutPointSourceId::BlockReward(Id::new(&generate_random_h256(g)))
    };

    TxInput::new(
        outpoint,
        g.next_u32(),
        InputWitness::Standard(StandardInputSignature::new(
            SigHashType::try_from(SigHashType::ALL).unwrap(),
            witness,
        )),
    )
}

fn generate_random_invalid_output(g: &mut impl crypto::random::Rng) -> TxOutput {
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    TxOutput::new(
        Amount::from_atoms(g.next_u64() as u128),
        Destination::PublicKey(pub_key),
    )
}

fn generate_random_invalid_transaction(rng: &mut impl crypto::random::Rng) -> Transaction {
    let inputs = {
        let input_count = 1 + (rng.next_u32() as usize) % 10;
        (0..input_count)
            .into_iter()
            .map(|_| generate_random_invalid_input(rng))
            .collect::<Vec<_>>()
    };

    let outputs = {
        let output_count = 1 + (rng.next_u32() as usize) % 10;
        (0..output_count)
            .into_iter()
            .map(|_| generate_random_invalid_output(rng))
            .collect::<Vec<_>>()
    };

    let flags = rng.next_u32();
    let lock_time = rng.next_u32();

    Transaction::new(flags, inputs, outputs, lock_time).expect("Creating tx caused fail")
}

fn generate_random_invalid_block() -> Block {
    let mut rng = crypto::random::make_pseudo_rng();

    let transactions = {
        let transaction_count = rng.next_u32() % 20;
        (0..transaction_count)
            .into_iter()
            .map(|_| generate_random_invalid_transaction(&mut rng))
            .collect::<Vec<_>>()
    };
    let time = rng.next_u32();
    let prev_id = Some(Id::new(&generate_random_h256(&mut rng)));

    Block::new(transactions, prev_id, time, ConsensusData::None)
        .expect("Creating block caused fail")
}

#[test]
fn test_indices_calculations() {
    let block = generate_random_invalid_block();
    let serialized_block = block.encode();
    let serialized_header = block.header().encode();
    let serialized_transactions = block.transactions().encode();
    assert_eq!(
        // +1 for the enum arm byte
        1 + serialized_header.len() + serialized_transactions.len(),
        serialized_block.len(),
    );
    // TODO: calculate block reward position
    for (tx_num, tx) in block.transactions().iter().enumerate() {
        let tx_index = calculate_tx_index_from_block(&block, tx_num).unwrap();
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(tx_index.get_output_count(), tx.get_outputs().len() as u32);

        let pos = match tx_index.get_position() {
            SpendablePosition::Transaction(pos) => pos,
            SpendablePosition::BlockReward(_) => unreachable!(),
        };
        let tx_start_pos = pos.get_byte_offset_in_block() as usize;
        let tx_end_pos =
            pos.get_byte_offset_in_block() as usize + pos.get_serialized_size() as usize;
        let tx_serialized_in_block = &serialized_block[tx_start_pos..tx_end_pos];
        let tx_serialized = tx.encode();
        assert_eq!(tx_serialized_in_block, tx_serialized);

        // to ensure Vec comparison is correct since I'm a paranoid C++ dude, let's mess things up
        let tx_messed = tx_serialized.iter().map(|c| c.wrapping_add(1)).collect::<Vec<u8>>();
        assert!(tx_serialized_in_block != tx_messed);
    }
}
