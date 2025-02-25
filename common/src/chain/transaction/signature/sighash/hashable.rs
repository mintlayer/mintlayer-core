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

use crate::{
    chain::{
        signature::{sighash::sighashtype, DestinationSigError},
        TxInput, TxOutput,
    },
    primitives::id::{hash_encoded_to, DefaultHashAlgoStream},
};

pub trait SignatureHashableElement {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), DestinationSigError>;
}

impl SignatureHashableElement for &[TxOutput] {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        _target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), DestinationSigError> {
        match mode.outputs_mode() {
            sighashtype::OutputsMode::All => {
                hash_encoded_to(self, stream);
            }
            sighashtype::OutputsMode::None => (),
            sighashtype::OutputsMode::Single => {
                let output = self.get(target_input_num).ok_or({
                    DestinationSigError::InvalidInputIndex(target_input_num, self.len())
                })?;
                hash_encoded_to(&output, stream);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SignatureHashableInputs<'a> {
    inputs: &'a [TxInput],
    /// Include utxos of the inputs to make it possible to verify the inputs scripts and amounts without downloading the full transactions
    /// It can be None which means that input spends from an account not utxo
    inputs_utxos: &'a [Option<&'a TxOutput>],
}

impl<'a> SignatureHashableInputs<'a> {
    pub fn new(
        inputs: &'a [TxInput],
        inputs_utxos: &'a [Option<&'a TxOutput>],
    ) -> Result<Self, DestinationSigError> {
        if inputs.len() != inputs_utxos.len() {
            return Err(DestinationSigError::InvalidUtxoCountVsInputs(
                inputs_utxos.len(),
                inputs.len(),
            ));
        }

        let result = Self {
            inputs,
            inputs_utxos,
        };

        Ok(result)
    }
}

impl SignatureHashableElement for SignatureHashableInputs<'_> {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), DestinationSigError> {
        if target_input_num >= self.inputs.len() {
            return Err(DestinationSigError::InvalidInputIndex(
                target_input_num,
                self.inputs.len(),
            ));
        }

        match mode.inputs_mode() {
            sighashtype::InputsMode::CommitWhoPays => {
                {
                    // Commit inputs
                    let inputs = self.inputs;
                    hash_encoded_to(&(inputs.len() as u32), stream);
                    for input in inputs {
                        hash_encoded_to(&input, stream);
                    }
                }

                {
                    // Commit inputs' utxos
                    let inputs_utxos = self.inputs_utxos;
                    hash_encoded_to(&(inputs_utxos.len() as u32), stream);
                    for input_utxo in inputs_utxos {
                        hash_encoded_to(&input_utxo, stream);
                    }
                }
            }
            sighashtype::InputsMode::AnyoneCanPay => {
                // Commit the input being signed (target input)
                hash_encoded_to(&target_input, stream);
                // Commit the utxo of the input being signed (target input)
                hash_encoded_to(&self.inputs_utxos[target_input_num], stream);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crypto::key::{KeyKind, PrivateKey};
    use randomness::{CryptoRng, Rng};
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use crate::{
        chain::{
            output_value::OutputValue, signature::sighash::sighashtype::SigHashType, Destination,
            OutPointSourceId,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::hash::StreamHasher;

    use super::*;

    fn generate_random_invalid_input(rng: &mut impl Rng) -> TxInput {
        let outpoint = if rng.next_u32() % 2 == 0 {
            OutPointSourceId::Transaction(Id::new(H256::random_using(rng)))
        } else {
            OutPointSourceId::BlockReward(Id::new(H256::random_using(rng)))
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

    fn do_test_hashable_inputs(
        inputs_count: usize,
        inputs_utxos_count: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        let inputs = (0..inputs_count)
            .map(|_| generate_random_invalid_input(rng))
            .collect::<Vec<_>>();

        let inputs_utxos = (0..inputs_utxos_count)
            .map(|_| generate_random_invalid_output(rng))
            .collect::<Vec<_>>();

        let inputs_utxos = inputs_utxos.iter().map(Some).collect::<Vec<_>>();

        let hashable_inputs_result = SignatureHashableInputs::new(&inputs, &inputs_utxos);

        if inputs_count == 0 {
            return;
        }

        if inputs_count != inputs_utxos_count {
            assert_eq!(
                hashable_inputs_result.unwrap_err(),
                DestinationSigError::InvalidUtxoCountVsInputs(inputs_utxos.len(), inputs.len(),)
            );
        } else {
            assert!(hashable_inputs_result.is_ok());

            let hashable_inputs = hashable_inputs_result.unwrap();

            let mut stream = DefaultHashAlgoStream::new();

            let index_to_hash = rng.gen_range(0..inputs.len());

            // Invalid input index
            assert!(hashable_inputs
                .signature_hash(
                    &mut stream,
                    SigHashType::all(),
                    &inputs[index_to_hash],
                    index_to_hash,
                )
                .is_ok(),);

            // Valid case
            assert_eq!(
                hashable_inputs.signature_hash(
                    &mut stream,
                    SigHashType::all(),
                    &inputs[index_to_hash],
                    inputs_count,
                ),
                Err(DestinationSigError::InvalidInputIndex(
                    inputs_count,
                    inputs.len(),
                ))
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn signature_hashable_inputs(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let inputs_count = rng.gen_range(0..100);
        let inputs_utxos_count = rng.gen_range(0..100);

        // invalid case
        do_test_hashable_inputs(inputs_count, inputs_utxos_count, &mut rng);

        // valid case
        do_test_hashable_inputs(inputs_count, inputs_count, &mut rng);
    }
}
