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

use itertools::Itertools;

use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::{CryptoRng, Rng};
use script::Script;
use serialization::{Decode, Encode};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        self,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{sighashtype::SigHashType, InputInfo},
            DestinationSigError, EvaluatedInputWitness, Signable,
        },
        signed_transaction::SignedTransaction,
        AccountNonce, AccountSpending, ChainConfig, DelegationId, Destination, OrderData, OrderId,
        PoolData, Transaction, TransactionCreationError, TxInput, TxOutput,
    },
    primitives::{amount::UnsignedIntType, per_thousand::PerThousand, Amount, Id, H256},
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
    let (private_key, public_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let output_value = OutputValue::Coin(Amount::from_atoms(rng.next_u64() as u128));
    let utxo = TxOutput::Transfer(output_value, destination);
    (utxo, private_key)
}

pub fn generate_order_data(
    rng: &mut (impl Rng + CryptoRng),
) -> (OrderData, crypto::key::PrivateKey) {
    let (private_key, public_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let conclude_key = Destination::PublicKey(public_key);
    let ask = make_random_value(rng);
    let give = make_random_value(rng);
    (OrderData::new(conclude_key, ask, give), private_key)
}

pub fn generate_pool_data(rng: &mut (impl Rng + CryptoRng)) -> (PoolData, crypto::key::PrivateKey) {
    let (private_key, public_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let decommission_destination = Destination::PublicKey(public_key);
    let pledge = Amount::from_atoms(rng.gen_range(100..1_000_000));
    let reward = Amount::from_atoms(rng.gen_range(100..1_000_000));
    let cost_per_block = Amount::from_atoms(rng.gen());
    (
        PoolData::new(
            decommission_destination,
            pledge,
            reward,
            vrf_pk,
            PerThousand::new_from_rng(rng),
            cost_per_block,
        ),
        private_key,
    )
}

#[derive(Clone, Debug, Encode, Decode, Eq, PartialEq)]
pub enum InputInfoVal {
    None,
    Utxo(TxOutput),
    Order {
        data: OrderData,
        ask_balance: Amount,
        give_balance: Amount,
    },
    Pool(PoolData),
}

impl<'a> Into<InputInfo<'a>> for &'a InputInfoVal {
    fn into(self) -> InputInfo<'a> {
        match self {
            InputInfoVal::None => InputInfo::None,
            InputInfoVal::Utxo(utxo) => InputInfo::Utxo(utxo),
            InputInfoVal::Order {
                data,
                ask_balance,
                give_balance,
            } => InputInfo::Order {
                data,
                ask_balance: *ask_balance,
                give_balance: *give_balance,
            },
            InputInfoVal::Pool(data) => InputInfo::Pool(data),
        }
    }
}

pub fn generate_inputs_infos(
    rng: &mut (impl Rng + CryptoRng),
    input_count: usize,
) -> (Vec<InputInfoVal>, Vec<Option<PrivateKey>>) {
    (0..input_count)
        .map(|_| match rng.gen_range(0..4) {
            0 => (InputInfoVal::None, None),
            1 => {
                let (utxo, priv_key) = generate_input_utxo(rng);
                (InputInfoVal::Utxo(utxo), Some(priv_key))
            }
            2 => {
                let (data, priv_key) = generate_order_data(rng);
                let ask_balance = Amount::from_atoms(rng.gen());
                let give_balance = Amount::from_atoms(rng.gen());
                (
                    InputInfoVal::Order {
                        data,
                        ask_balance,
                        give_balance,
                    },
                    Some(priv_key),
                )
            }
            3 => {
                let (data, priv_key) = generate_pool_data(rng);
                (InputInfoVal::Pool(data), Some(priv_key))
            }
            _ => unreachable!(),
        })
        .unzip()
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
    inputs_info: &[InputInfo],
    outputs_count: usize,
) -> Result<Transaction, TransactionCreationError> {
    let inputs = inputs_info
        .iter()
        .map(|info| match info {
            InputInfo::None => TxInput::from_account(
                AccountNonce::new(rng.gen()),
                AccountSpending::DelegationBalance(
                    DelegationId::new(H256::random_using(rng)),
                    Amount::from_atoms(rng.gen()),
                ),
            ),
            InputInfo::Utxo(_) | InputInfo::Pool(_) => TxInput::from_utxo(
                Id::<Transaction>::new(H256::random_using(rng)).into(),
                rng.gen(),
            ),
            InputInfo::Order { .. } => {
                TxInput::OrderAccountCommand(chain::OrderAccountCommand::FillOrder(
                    OrderId::new(H256::random_using(rng)),
                    Amount::from_atoms(rng.gen()),
                    Destination::AnyoneCanSpend,
                ))
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
    inputs_info: &[InputInfo],
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
                inputs_info,
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
    inputs_info: &[InputInfo],
    outputs: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
) -> Result<SignedTransaction, TransactionCreationError> {
    let tx = generate_unsigned_tx(rng, destination, inputs_info, outputs).unwrap();
    let signed_tx =
        sign_whole_tx(rng, tx, inputs_info, private_key, sighash_type, destination).unwrap();
    assert_eq!(
        verify_signed_tx(chain_config, &signed_tx, inputs_info, destination),
        Ok(())
    );
    Ok(signed_tx)
}

pub fn make_signature(
    rng: &mut (impl Rng + CryptoRng),
    tx: &Transaction,
    inputs_info: &[InputInfo],
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
        inputs_info,
        input_num,
        rng,
    )?;
    Ok(input_sig)
}

pub fn verify_signed_tx(
    chain_config: &ChainConfig,
    tx: &SignedTransaction,
    inputs_info: &[InputInfo],
    destination: &Destination,
) -> Result<(), DestinationSigError> {
    for i in 0..tx.inputs().len() {
        verify_signature(
            chain_config,
            destination,
            tx,
            &tx.signatures()[i],
            inputs_info,
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
    inputs_info: &[InputInfo],
    input_num: usize,
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
        inputs_info,
        input_num,
    )
}
