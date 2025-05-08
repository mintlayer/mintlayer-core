// Copyright (c) 2025 RBB S.r.l
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

use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::chain::{
    signature::{
        inputsig::{standard_signature::StandardInputSignature, InputWitness},
        sighash::sighashtype::SigHashType,
    },
    OutPointSourceId, SignedTransaction, Transaction, TxInput,
};
use crate::primitives::{Amount, Id};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn estimate_tx_size(
    #[case] seed: Seed,
    #[values(1..64, 64..0x4000, 0x4000..0x4001)] inputs_range: std::ops::Range<u32>,
    #[values(1..64, 64..0x4000, 0x4000..0x4001)] outputs_range: std::ops::Range<u32>,
) {
    use crypto::key::{KeyKind, PrivateKey};
    use serialization::Encode;

    use crate::{
        chain::{
            output_value::OutputValue,
            signature::inputsig::authorize_pubkey_spend::AuthorizedPublicKeySpend, Destination,
            TxOutput,
        },
        size_estimation::tx_size_with_num_inputs_and_outputs,
    };

    let mut rng = make_seedable_rng(seed);

    let num_inputs = rng.gen_range(inputs_range);
    let inputs = (0..num_inputs)
        .map(|_| {
            TxInput::from_utxo(
                OutPointSourceId::Transaction(Id::random_using(&mut rng)),
                rng.gen_range(0..100),
            )
        })
        .collect();

    let num_outputs = rng.gen_range(outputs_range);
    let outputs = (0..num_outputs)
        .map(|_| {
            let destination = Destination::PublicKey(
                crypto::key::PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1,
            );

            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1..10000))),
                destination,
            )
        })
        .collect();

    let tx = Transaction::new(0, inputs, outputs).unwrap();
    let signatures = (0..num_inputs)
        .map(|_| {
            let private_key =
                PrivateKey::new_from_rng(&mut rng, crypto::key::KeyKind::Secp256k1Schnorr).0;
            let signature = private_key.sign_message(&[0; 32], &mut rng).unwrap();
            let raw_signature = AuthorizedPublicKeySpend::new(signature).encode();
            let standard = StandardInputSignature::new(SigHashType::all(), raw_signature);
            InputWitness::Standard(standard)
        })
        .collect();
    let tx = SignedTransaction::new(tx, signatures).unwrap();

    let estimated_tx_size =
        tx_size_with_num_inputs_and_outputs(num_outputs as usize, num_inputs as usize).unwrap()
            + tx.inputs().iter().map(Encode::encoded_size).sum::<usize>()
            + tx.signatures().iter().map(Encode::encoded_size).sum::<usize>()
            + tx.outputs().iter().map(Encode::encoded_size).sum::<usize>();

    let expected_tx_size = Encode::encoded_size(&tx);

    assert_eq!(estimated_tx_size, expected_tx_size);
}
