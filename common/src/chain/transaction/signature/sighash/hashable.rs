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

use utils::ensure;

use crate::{
    chain::{
        signature::{sighash::sighashtype, DestinationSigError},
        TxInput, TxOutput,
    },
    primitives::id::{hash_encoded_to, DefaultHashAlgoStream},
};

use super::SighashInputCommitment;

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
    input_commitments: &'a [SighashInputCommitment<'a>],
}

impl<'a> SignatureHashableInputs<'a> {
    pub fn new(
        inputs: &'a [TxInput],
        input_commitments: &'a [SighashInputCommitment<'a>],
    ) -> Result<Self, DestinationSigError> {
        ensure!(
            input_commitments.len() == inputs.len(),
            DestinationSigError::InvalidUtxoCountVsInputs(input_commitments.len(), inputs.len())
        );

        let result = Self {
            inputs,
            input_commitments,
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
        target_input_index: usize,
    ) -> Result<(), DestinationSigError> {
        ensure!(
            target_input_index < self.inputs.len(),
            DestinationSigError::InvalidInputIndex(target_input_index, self.inputs.len(),)
        );

        match mode.inputs_mode() {
            sighashtype::InputsMode::CommitWhoPays => {
                {
                    // Commit inputs
                    hash_encoded_to(&(self.inputs.len() as u32), stream);
                    for input in self.inputs {
                        hash_encoded_to(&input, stream);
                    }
                }

                {
                    // Commit the extra commitments
                    hash_encoded_to(&(self.input_commitments.len() as u32), stream);
                    for input_info in self.input_commitments {
                        hash_encoded_to(&input_info, stream);
                    }
                }
            }
            sighashtype::InputsMode::AnyoneCanPay => {
                // Commit the input being signed (target input)
                hash_encoded_to(&target_input, stream);
                // Commit the extra commitment of the input being signed (target input)
                hash_encoded_to(&self.input_commitments[target_input_index], stream);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools as _;
    use randomness::{CryptoRng, Rng};
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use crate::{
        chain::{
            signature::{
                sighash::{sighashtype::SigHashType, SighashInputCommitment},
                tests::utils::{generate_input_commitments, generate_inputs_utxos},
            },
            OutPointSourceId,
        },
        primitives::{Id, H256},
    };
    use crypto::hash::StreamHasher;

    use super::*;

    #[derive(Debug, Clone)]
    pub struct SignatureHashableInputsDeprecated<'a> {
        inputs: &'a [TxInput],
        inputs_utxos: &'a [Option<&'a TxOutput>],
    }

    impl SignatureHashableElement for SignatureHashableInputsDeprecated<'_> {
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

    fn generate_random_input(rng: &mut impl Rng) -> TxInput {
        let outpoint = if rng.gen::<bool>() {
            OutPointSourceId::Transaction(Id::new(H256::random_using(rng)))
        } else {
            OutPointSourceId::BlockReward(Id::new(H256::random_using(rng)))
        };

        TxInput::from_utxo(outpoint, rng.next_u32())
    }

    fn do_test_hashable_inputs(
        inputs_count: usize,
        inputs_utxos_count: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        let inputs = (0..inputs_count).map(|_| generate_random_input(rng)).collect::<Vec<_>>();

        let input_commitment_vals = generate_input_commitments(rng, inputs_utxos_count);
        let input_commitments = input_commitment_vals.iter().map(|comm| comm.into()).collect_vec();

        let hashable_inputs_result = SignatureHashableInputs::new(&inputs, &input_commitments);

        if inputs_count != inputs_utxos_count {
            assert_eq!(
                hashable_inputs_result.unwrap_err(),
                DestinationSigError::InvalidUtxoCountVsInputs(
                    input_commitments.len(),
                    inputs.len(),
                )
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
                .is_ok());

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
    fn signature_hashable_inputs_utxo_refs(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let inputs_count = rng.gen_range(1..100);
        let inputs_utxos_count = rng.gen_range(0..100);

        // invalid case
        do_test_hashable_inputs(inputs_count, inputs_utxos_count, &mut rng);

        // valid case
        do_test_hashable_inputs(inputs_count, inputs_count, &mut rng);
    }

    // Make sure that new signature_hash produces the same hash as the old one
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn signature_hash_backward_compatibility(#[case] seed: Seed) {
        use std::borrow::Cow;

        use crate::chain::signature::tests::utils::sig_hash_types;

        let mut rng = make_seedable_rng(seed);

        for sighash_type in sig_hash_types() {
            let inputs_count = rng.gen_range(1..100);
            let inputs =
                (0..inputs_count).map(|_| generate_random_input(&mut rng)).collect::<Vec<_>>();
            let (inputs_utxos, _) = generate_inputs_utxos(&mut rng, inputs_count);

            let inputs_utxos_refs = inputs_utxos.iter().map(|u| u.as_ref()).collect::<Vec<_>>();

            let hashable_inputs_1 = SignatureHashableInputsDeprecated {
                inputs: &inputs,
                inputs_utxos: &inputs_utxos_refs,
            };

            let input_index = rng.gen_range(0..inputs_count);

            let mut stream1 = DefaultHashAlgoStream::new();
            hashable_inputs_1
                .signature_hash(
                    &mut stream1,
                    sighash_type,
                    &inputs[input_index],
                    input_index,
                )
                .unwrap();
            let hash1: H256 = stream1.finalize().into();

            let inputs_info = inputs_utxos_refs
                .iter()
                .map(|utxo| {
                    utxo.map_or(SighashInputCommitment::None, |utxo| {
                        SighashInputCommitment::Utxo(Cow::Borrowed(utxo))
                    })
                })
                .collect::<Vec<_>>();
            let hashable_inputs_2 = SignatureHashableInputs::new(&inputs, &inputs_info).unwrap();

            let mut stream2 = DefaultHashAlgoStream::new();
            hashable_inputs_2
                .signature_hash(
                    &mut stream2,
                    sighash_type,
                    &inputs[input_index],
                    input_index,
                )
                .unwrap();
            let hash2: H256 = stream2.finalize().into();

            assert_eq!(hash1, hash2);
        }
    }
}
