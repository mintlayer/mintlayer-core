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
    SignedTransaction, Transaction,
    partially_signed_transaction::{
        PartiallySignedTransaction, PartiallySignedTransactionConsistencyCheck,
        PartiallySignedTransactionError,
    },
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
        if let Ok(ptx) = PartiallySignedTransaction::decode_all(&mut &bytes[..]) {
            // Decoding bypasses the invariants that `PartiallySignedTransaction::new`
            // enforces, so a malformed (but still decodable) transaction could later make
            // the wallet panic, e.g. on a witness/input count mismatch. Reject it here.
            //
            // `Basic` only checks the structural invariants that prevent such panics; the
            // stricter additional-info checks are intentionally not used here so that a
            // transaction that is still being assembled (and may not carry all of its input
            // utxos or additional info yet) is not rejected.
            ptx.ensure_consistency(PartiallySignedTransactionConsistencyCheck::Basic)
                .map_err(GenericTransactionError::InconsistentPartiallySignedTransaction)?;
            Ok(Self::Partial(ptx))
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

    #[error("Inconsistent partially signed transaction: {0}")]
    InconsistentPartiallySignedTransaction(PartiallySignedTransactionError),
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use common::{
        chain::{
            Destination, OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
            htlc::HtlcSecret,
            output_value::OutputValue,
            partially_signed_transaction::{
                PartiallySignedTransactionConsistencyCheck, PartiallySignedTransactionError,
                TxAdditionalInfo,
            },
            signature::inputsig::InputWitness,
        },
        primitives::{Amount, Id},
    };
    use serialization::Encode;
    use test_utils::random::{RngExt as _, Seed, gen_random_bytes, make_seedable_rng};

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_decode_from_untagged_bytes(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let tx = Transaction::new(
            rng.random(),
            vec![TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.random(),
            ))],
            vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(rng.random())))],
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

    // A PartiallySignedTransaction that is decodable but violates the invariants that
    // `new` normally enforces must be rejected, otherwise the wallet could later panic
    // on it. Such a transaction can't be built through the public constructor, so its
    // bytes are assembled by hand here to mimic malformed external input.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_decode_rejects_inconsistent_partially_signed_transaction(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let tx = Transaction::new(
            rng.random(),
            vec![TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.random(),
            ))],
            vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(rng.random())))],
        )
        .unwrap();

        // Encode a PartiallySignedTransactionV1 field by field, but give it an empty
        // `witnesses` vector while the transaction has one input, so the witness count
        // no longer matches the input count.
        let mut bytes = Vec::new();
        64u8.encode_to(&mut bytes); // PartiallySignedTransaction::V1 discriminant (codec index 64)
        tx.encode_to(&mut bytes);
        Vec::<Option<InputWitness>>::new().encode_to(&mut bytes); // witnesses
        vec![Option::<TxOutput>::None].encode_to(&mut bytes); // input_utxos
        vec![Option::<Destination>::None].encode_to(&mut bytes); // destinations
        vec![Option::<HtlcSecret>::None].encode_to(&mut bytes); // htlc_secrets
        TxAdditionalInfo::new().encode_to(&mut bytes);

        let err = GenericTransaction::decode_from_untagged_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            GenericTransactionError::InconsistentPartiallySignedTransaction(
                PartiallySignedTransactionError::InvalidWitnessCount
            )
        );
    }
}
