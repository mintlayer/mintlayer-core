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

use std::borrow::Cow;

use itertools::Itertools;

use crypto::key::{KeyKind, PrivateKey, PublicKey};
use randomness::{CryptoRng, Rng};
use script::Script;

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        self,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{input_commitment::SighashInputCommitment, sighashtype::SigHashType},
            DestinationSigError, EvaluatedInputWitness, Signable,
        },
        signed_transaction::SignedTransaction,
        AccountNonce, AccountSpending, ChainConfig, DelegationId, Destination, Transaction,
        TransactionCreationError, TxInput, TxOutput,
    },
    primitives::{amount::UnsignedIntType, Amount, Id, H256},
};

fn make_random_value(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    if rng.gen::<bool>() {
        OutputValue::Coin(Amount::from_atoms(rng.gen()))
    } else {
        OutputValue::TokenV1(H256(rng.gen()).into(), Amount::from_atoms(rng.gen()))
    }
}

pub fn generate_input_utxo(
    rng: &mut (impl Rng + CryptoRng),
) -> (TxOutput, crypto::key::PrivateKey) {
    let (sk, pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(pk);
    let output_value = OutputValue::Coin(Amount::from_atoms(rng.next_u64() as u128));
    let utxo = TxOutput::Transfer(output_value, destination);
    (utxo, sk)
}

// FIXME: remove and use SighashInputCommitment directly instead?
#[derive(Clone, Debug)]
pub enum InputCommitmentVal {
    None,
    Utxo(TxOutput),
    ProduceBlockFromStakeUtxo {
        utxo: TxOutput,
        staker_balance: Amount,
    },
    FillOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
    },
    ConcludeOrderAccountCommand {
        ask_balance: Amount,
        give_balance: Amount,
    },
}

impl<'a> Into<SighashInputCommitment<'a>> for &'a InputCommitmentVal {
    fn into(self) -> SighashInputCommitment<'a> {
        match self {
            InputCommitmentVal::None => SighashInputCommitment::None,
            InputCommitmentVal::Utxo(utxo) => SighashInputCommitment::Utxo(Cow::Borrowed(utxo)),
            InputCommitmentVal::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            } => SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo: Cow::Borrowed(utxo),
                staker_balance: *staker_balance,
            },
            InputCommitmentVal::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            } => SighashInputCommitment::FillOrderAccountCommand {
                initially_asked: initially_asked.clone(),
                initially_given: initially_given.clone(),
            },
            InputCommitmentVal::ConcludeOrderAccountCommand {
                ask_balance,
                give_balance,
            } => SighashInputCommitment::ConcludeOrderAccountCommand {
                ask_balance: *ask_balance,
                give_balance: *give_balance,
            },
        }
    }
}

pub fn generate_input_commitment(rng: &mut (impl Rng + CryptoRng)) -> InputCommitmentVal {
    match rng.gen_range(0..5) {
        0 => InputCommitmentVal::None,
        1 => {
            let (utxo, _) = generate_input_utxo(rng);
            InputCommitmentVal::Utxo(utxo)
        }
        2 => {
            let (utxo, _) = generate_input_utxo(rng);
            let staker_balance = Amount::from_atoms(rng.gen::<UnsignedIntType>());
            InputCommitmentVal::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            }
        }
        3 => {
            let initially_asked = make_random_value(rng);
            let initially_given = make_random_value(rng);

            InputCommitmentVal::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            }
        }
        4 => {
            let ask_balance = Amount::from_atoms(rng.gen());
            let give_balance = Amount::from_atoms(rng.gen());

            InputCommitmentVal::ConcludeOrderAccountCommand {
                ask_balance,
                give_balance,
            }
        }
        _ => unreachable!(),
    }
}

pub fn generate_input_commitments(
    rng: &mut (impl Rng + CryptoRng),
    input_count: usize,
) -> Vec<InputCommitmentVal> {
    (0..input_count).map(|_| generate_input_commitment(rng)).collect()
}

pub fn generate_inputs_utxos(
    rng: &mut (impl Rng + CryptoRng),
    input_count: usize,
) -> (Vec<Option<TxOutput>>, Vec<Option<PrivateKey>>) {
    (0..input_count)
        .map(|_| {
            if rng.gen::<bool>() {
                let (utxo, priv_key) = generate_input_utxo(rng);
                (Some(utxo), Some(priv_key))
            } else {
                (None, None)
            }
        })
        .unzip()
}

// This is required because we can't access private fields of the Transaction class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutableTransaction {
    pub flags: u128,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub witness: Vec<InputWitness>,
}

impl From<&SignedTransaction> for MutableTransaction {
    fn from(tx: &SignedTransaction) -> Self {
        Self {
            flags: tx.flags(),
            inputs: tx.inputs().to_owned(),
            outputs: tx.outputs().to_owned(),
            witness: tx.signatures().to_vec(),
        }
    }
}

impl MutableTransaction {
    pub fn generate_tx(&self) -> Result<SignedTransaction, TransactionCreationError> {
        SignedTransaction::new(
            Transaction::new(self.flags, self.inputs.clone(), self.outputs.clone()).unwrap(),
            self.witness.clone(),
        )
    }
}

pub fn generate_unsigned_tx(
    rng: &mut (impl Rng + CryptoRng),
    destination: &Destination,
    inputs_count: usize,
    outputs_count: usize,
) -> Result<Transaction, TransactionCreationError> {
    let inputs = (0..inputs_count)
        .map(|_| {
            if rng.gen_bool(0.5) {
                TxInput::from_utxo(
                    Id::<Transaction>::new(H256::random_using(rng)).into(),
                    rng.gen(),
                )
            } else {
                TxInput::from_account(
                    AccountNonce::new(rng.gen()),
                    AccountSpending::DelegationBalance(
                        DelegationId::new(H256::random_using(rng)),
                        Amount::from_atoms(rng.gen()),
                    ),
                )
            }
        })
        .collect();

    let outputs = std::iter::from_fn(|| {
        Some(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen::<UnsignedIntType>())),
            destination.clone(),
        ))
    })
    .take(outputs_count)
    .collect();

    let tx = Transaction::new(rng.gen(), inputs, outputs)?;
    Ok(tx)
}

pub fn sign_whole_tx(
    rng: &mut (impl Rng + CryptoRng),
    tx: Transaction,
    input_commitments: &[SighashInputCommitment],
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    destination: &Destination,
) -> Result<SignedTransaction, DestinationSigError> {
    let sigs: Result<Vec<StandardInputSignature>, DestinationSigError> = tx
        .inputs()
        .iter()
        .enumerate()
        .map(|(i, _input)| {
            make_signature(
                rng,
                &tx,
                input_commitments,
                i,
                private_key,
                sighash_type,
                destination.clone(),
            )
        })
        .collect();
    let witnesses = sigs?.into_iter().map(InputWitness::Standard).collect_vec();

    SignedTransaction::new(tx, witnesses).map_err(|_| DestinationSigError::InvalidWitnessCount)
}

pub fn generate_and_sign_tx(
    chain_config: &ChainConfig,
    rng: &mut (impl Rng + CryptoRng),
    destination: &Destination,
    input_commitments: &[SighashInputCommitment],
    outputs: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
) -> Result<SignedTransaction, TransactionCreationError> {
    let tx = generate_unsigned_tx(rng, destination, input_commitments.len(), outputs).unwrap();
    let signed_tx = sign_whole_tx(
        rng,
        tx,
        input_commitments,
        private_key,
        sighash_type,
        destination,
    )
    .unwrap();
    assert_eq!(
        verify_signed_tx(chain_config, &signed_tx, input_commitments, destination),
        Ok(())
    );
    Ok(signed_tx)
}

pub fn make_signature(
    rng: &mut (impl Rng + CryptoRng),
    tx: &Transaction,
    input_commitments: &[SighashInputCommitment],
    input_num: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    outpoint_dest: Destination,
) -> Result<StandardInputSignature, DestinationSigError> {
    let input_sig = StandardInputSignature::produce_uniparty_signature_for_input(
        private_key,
        sighash_type,
        outpoint_dest,
        tx,
        input_commitments,
        input_num,
        rng,
    )?;
    Ok(input_sig)
}

pub fn verify_signed_tx(
    chain_config: &ChainConfig,
    tx: &SignedTransaction,
    input_commitments: &[SighashInputCommitment],
    destination: &Destination,
) -> Result<(), DestinationSigError> {
    for i in 0..tx.inputs().len() {
        verify_signature(
            chain_config,
            destination,
            tx,
            &tx.signatures()[i],
            input_commitments,
            i,
        )?
    }
    Ok(())
}

/// Returns an iterator over all possible signature hash types.
pub fn sig_hash_types() -> impl Iterator<Item = SigHashType> + Clone {
    [
        SigHashType::try_from(SigHashType::ALL),
        SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY),
        SigHashType::try_from(SigHashType::NONE),
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY),
        SigHashType::try_from(SigHashType::SINGLE),
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY),
    ]
    .into_iter()
    .map(Result::unwrap)
}

/// Returns an iterator over all possible destinations.
pub fn destinations(
    rng: &mut impl Rng,
    public_key: PublicKey,
) -> impl Iterator<Item = Destination> {
    // TODO: find a way to write this such that it loops over all possible arms instead of doing this manually
    [
        Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
        Destination::PublicKey(public_key),
        Destination::AnyoneCanSpend,
        Destination::ScriptHash(Id::<Script>::from(H256::random_using(rng))),
    ]
    .into_iter()
}

pub fn verify_signature<T: Signable>(
    chain_config: &ChainConfig,
    outpoint_destination: &Destination,
    tx: &T,
    input_witness: &InputWitness,
    input_commitments: &[SighashInputCommitment],
    input_index: usize,
) -> Result<(), DestinationSigError> {
    let eval_witness = match input_witness.clone() {
        InputWitness::NoSignature(d) => EvaluatedInputWitness::NoSignature(d),
        InputWitness::Standard(s) => EvaluatedInputWitness::Standard(s),
    };
    chain::signature::verify_signature(
        chain_config,
        outpoint_destination,
        tx,
        &eval_witness,
        input_commitments,
        input_index,
    )
}
