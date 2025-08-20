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

use super::{
    signature::{inputsig::InputWitness, Signable, Transactable},
    Transaction, TransactionSize, TxOutput,
};
use crate::{
    chain::{TransactionCreationError, TxInput},
    primitives::id::{self, H256},
};
use serialization::{Decode, Encode};
use utils::ensure;

#[derive(Debug, Clone, PartialEq, Eq, Encode, serde::Serialize)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: Vec<InputWitness>,
}

impl SignedTransaction {
    pub fn new(
        transaction: Transaction,
        signatures: Vec<InputWitness>,
    ) -> Result<Self, TransactionCreationError> {
        ensure!(
            signatures.len() == transaction.inputs().len(),
            TransactionCreationError::InvalidWitnessCount
        );
        Ok(Self {
            transaction,
            signatures,
        })
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn take_transaction(self) -> Transaction {
        self.transaction
    }

    pub fn version_byte(&self) -> u8 {
        self.transaction.version_byte()
    }

    pub fn is_replaceable(&self) -> bool {
        self.transaction.is_replaceable()
    }

    pub fn flags(&self) -> u128 {
        self.transaction.flags()
    }

    pub fn inputs(&self) -> &[TxInput] {
        self.transaction.inputs()
    }

    pub fn outputs(&self) -> &[TxOutput] {
        self.transaction.outputs()
    }

    pub fn has_smart_contracts(&self) -> bool {
        self.transaction.has_smart_contracts()
    }

    pub fn transaction_data_size(&self) -> TransactionSize {
        if self.has_smart_contracts() {
            TransactionSize::SmartContractTransaction(self.encoded_size())
        } else {
            TransactionSize::ScriptedTransaction(self.encoded_size())
        }
    }

    pub fn signatures(&self) -> &[InputWitness] {
        self.signatures.as_ref()
    }

    /// provides the hash of a transaction including the witness (malleable)
    pub fn serialized_hash(&self) -> H256 {
        id::hash_encoded(self)
    }
}

impl Signable for SignedTransaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.version_byte())
    }

    fn flags(&self) -> Option<u128> {
        Some(self.flags())
    }
}

impl Transactable for SignedTransaction {
    fn signatures(&self) -> Vec<Option<InputWitness>> {
        self.signatures.iter().map(|s| Some(s.clone())).collect()
    }
}

impl Decode for SignedTransaction {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let transaction = Transaction::decode(input)?;
        let witness = Vec::<InputWitness>::decode(input)?;
        if witness.len() != transaction.inputs().len() {
            let err = format!("{} != {}", witness.len(), transaction.inputs().len());
            return Err(serialization::Error::from(
                "Invalid witness count for transaction: Mismatch with input count",
            )
            .chain(err));
        }
        Ok(Self {
            transaction,
            signatures: witness,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::Amount;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    use super::*;

    use crate::chain::output_value::OutputValue;
    use crate::chain::TxInput;
    use crate::primitives::id::Id;
    use crate::primitives::H256;

    #[test]
    fn require_inputs_witnesses_same_size() {
        let hash0 = H256([0x50; 32]);
        let hash1 = H256([0x51; 32]);
        let hash2 = H256([0x52; 32]);

        let ins0: Vec<TxInput> =
            [TxInput::from_utxo(Id::<Transaction>::new(hash0).into(), 5)].to_vec();
        let ins1: Vec<TxInput> = [
            TxInput::from_utxo(Id::<Transaction>::new(hash1).into(), 3),
            TxInput::from_utxo(Id::<Transaction>::new(hash2).into(), 0),
        ]
        .to_vec();

        {
            let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
            assert!(SignedTransaction::new(tx.clone(), vec![]).is_ok());
            assert_eq!(
                SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]),
                Err(TransactionCreationError::InvalidWitnessCount)
            );
        }
        {
            let tx = Transaction::new(0x00, ins0, vec![]).unwrap();
            assert!(
                SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)]).is_ok()
            );
            assert_eq!(
                SignedTransaction::new(tx, vec![]),
                Err(TransactionCreationError::InvalidWitnessCount)
            );
        }
        {
            let tx = Transaction::new(0x00, ins1, vec![]).unwrap();
            assert!(SignedTransaction::new(
                tx.clone(),
                vec![
                    InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
                    InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
                ],
            )
            .is_ok());
            assert_eq!(
                SignedTransaction::new(
                    tx.clone(),
                    vec![InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09]))]
                ),
                Err(TransactionCreationError::InvalidWitnessCount)
            );
            assert_eq!(
                SignedTransaction::new(tx, vec![]),
                Err(TransactionCreationError::InvalidWitnessCount)
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn ensure_sane_encoding(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        // The only reason a manual decode is done is to enforce witness rules, hence we double check that round-trip encoding works
        let input_count = 1 + rng.gen::<usize>() % 10;
        let inputs = (0..input_count)
            .map(|_| {
                TxInput::from_utxo(
                    Id::<Transaction>::new(H256::random_using(&mut rng)).into(),
                    rng.gen::<u32>() % 10,
                )
            })
            .collect::<Vec<_>>();

        let output_count = 1 + rng.gen::<usize>() % 10;
        let outputs = (0..output_count)
            .map(|_| {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(rng.gen::<u128>())),
                    crate::chain::Destination::AnyoneCanSpend,
                )
            })
            .collect::<Vec<_>>();

        let witnesses = (0..input_count)
            .map(|_| {
                let witness_size = 1 + rng.gen::<usize>() % 100;
                let witness = (0..witness_size).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
                InputWitness::NoSignature(Some(witness))
            })
            .collect::<Vec<_>>();

        // Witness count that isn't equal to the input count
        let invalid_witness_count = loop {
            let invalid_witness_count = rng.gen::<usize>() % input_count;
            if invalid_witness_count != witnesses.len() {
                break invalid_witness_count;
            }
        };

        let invalid_witnesses = (0..invalid_witness_count)
            .map(|_| {
                let witness_size = 1 + rng.gen::<usize>() % 100;
                let witness = (0..witness_size).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
                InputWitness::NoSignature(Some(witness))
            })
            .collect::<Vec<_>>();

        {
            let flags = rng.gen::<u128>();

            let tx = Transaction::new(flags, inputs, outputs).unwrap();
            let signed_tx = SignedTransaction::new(tx, witnesses).unwrap();

            let encoded = signed_tx.encode();
            let decoded_signed_tx = SignedTransaction::decode(&mut encoded.as_slice()).unwrap();
            assert_eq!(signed_tx, decoded_signed_tx);

            // let's manually reconstruct an invalid case with invalid witness count
            let mut signed_tx = signed_tx;
            signed_tx.signatures = invalid_witnesses;
            let encoded = signed_tx.encode();
            SignedTransaction::decode(&mut encoded.as_slice()).unwrap_err();
        }
    }
}
