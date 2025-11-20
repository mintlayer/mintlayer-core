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

use common::chain::{
    partially_signed_transaction::PartiallySignedTransaction, SignedTransaction, Transaction,
};
use serialization::DecodeAll as _;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenericTransaction {
    Tx(Transaction),
    Partial(PartiallySignedTransaction),
    Signed(SignedTransaction),
}

impl GenericTransaction {
    pub fn decode_from_untagged_bytes(bytes: &[u8]) -> Result<Self, GenericTransactionError> {
        // Note: PartiallySignedTransaction's encoded form's first byte is always different
        // from the first byte of Transaction/SignedTransaction, so it can't be confused
        // with them.
        // On the other hand, SignedTransaction starts with Transaction. But since the former
        // has an extra field, it's always bigger than the latter. By using `decode_all` we
        // make sure that these 2 can't be confused with each other either.
        // I.e. the order in which the decoding attempts are performed here doesn't matter.
        if let Ok(tx) = PartiallySignedTransaction::decode_all(&mut &bytes[..]) {
            Ok(Self::Partial(tx))
        } else if let Ok(stx) = SignedTransaction::decode_all(&mut &bytes[..]) {
            Ok(Self::Signed(stx))
        } else if let Ok(tx) = Transaction::decode_all(&mut &bytes[..]) {
            Ok(Self::Tx(tx))
        } else {
            Err(GenericTransactionError::CannotDecodeFromUntaggedBytes)
        }
    }
}

#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum GenericTransactionError {
    #[error("The provided bytes are not an encoded transaction")]
    CannotDecodeFromUntaggedBytes,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use common::{
        chain::{
            output_value::OutputValue,
            partially_signed_transaction::{
                PartiallySignedTransactionConsistencyCheck, TxAdditionalInfo,
            },
            signature::inputsig::InputWitness,
            OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
        },
        primitives::{Amount, Id},
    };
    use serialization::Encode;
    use test_utils::random::{gen_random_bytes, make_seedable_rng, Rng, Seed};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_decode_from_untagged_bytes(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let tx = Transaction::new(
            rng.gen(),
            vec![TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.r#gen(),
            ))],
            vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(rng.r#gen())))],
        )
        .unwrap();

        let stx = SignedTransaction::new(
            tx.clone(),
            vec![InputWitness::NoSignature(Some(gen_random_bytes(&mut rng, 10, 20)))],
        )
        .unwrap();

        let ptx = PartiallySignedTransaction::new(
            tx.clone(),
            vec![None],
            vec![None],
            vec![None],
            None,
            TxAdditionalInfo::new(),
            PartiallySignedTransactionConsistencyCheck::Basic,
        )
        .unwrap();

        let encoded_tx = tx.encode();
        let encoded_stx = stx.encode();
        let encoded_ptx = ptx.encode();

        // Sanity check - the first byte of a PartiallySignedTransaction differs from that of
        // a Transaction.
        assert_ne!(encoded_ptx[0], encoded_tx[0]);

        let decoded_tx = GenericTransaction::decode_from_untagged_bytes(&encoded_tx).unwrap();
        assert_eq!(decoded_tx, GenericTransaction::Tx(tx));

        let decoded_stx = GenericTransaction::decode_from_untagged_bytes(&encoded_stx).unwrap();
        assert_eq!(decoded_stx, GenericTransaction::Signed(stx));

        let decoded_ptx = GenericTransaction::decode_from_untagged_bytes(&encoded_ptx).unwrap();
        assert_eq!(decoded_ptx, GenericTransaction::Partial(ptx));

        let err =
            GenericTransaction::decode_from_untagged_bytes("invalid bytes".as_bytes()).unwrap_err();
        assert_eq!(err, GenericTransactionError::CannotDecodeFromUntaggedBytes);
    }
}
