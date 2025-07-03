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
use strum::IntoEnumIterator as _;

use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey},
};
use randomness::{seq::IteratorRandom as _, CryptoRng, Rng};
use script::Script;
use test_utils::{random::gen_random_bytes, random_ascii_alphanumeric_string};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        self,
        htlc::{HashedTimelockContract, HtlcSecretHash},
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::{
                input_commitments::{SighashInputCommitment, SighashInputCommitmentTag},
                sighashtype::SigHashType,
            },
            DestinationSigError, EvaluatedInputWitness, Signable,
        },
        signed_transaction::SignedTransaction,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        AccountNonce, AccountSpending, ChainConfig, DelegationId, Destination, OrderData, PoolId,
        Transaction, TransactionCreationError, TxInput, TxOutput, TxOutputTag,
    },
    primitives::{amount::UnsignedIntType, per_thousand::PerThousand, Amount, Id, H256},
};

fn make_random_output_value(rng: &mut (impl Rng + CryptoRng)) -> OutputValue {
    if rng.gen::<bool>() {
        OutputValue::Coin(Amount::from_atoms(rng.gen()))
    } else {
        OutputValue::TokenV1(H256(rng.gen()).into(), Amount::from_atoms(rng.gen()))
    }
}

fn make_random_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    Destination::PublicKey(make_random_pub_key(rng))
}

fn make_random_pub_key(rng: &mut (impl Rng + CryptoRng)) -> PublicKey {
    PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1
}

fn make_random_vrf_pub_key(rng: &mut (impl Rng + CryptoRng)) -> VRFPublicKey {
    VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel).1
}

pub fn generate_input_utxo_for_tag(rng: &mut (impl Rng + CryptoRng), tag: TxOutputTag) -> TxOutput {
    match tag {
        TxOutputTag::Transfer => {
            TxOutput::Transfer(make_random_output_value(rng), make_random_destination(rng))
        }
        TxOutputTag::LockThenTransfer => TxOutput::LockThenTransfer(
            make_random_output_value(rng),
            make_random_destination(rng),
            OutputTimeLock::ForBlockCount(rng.gen()),
        ),
        TxOutputTag::Burn => TxOutput::Burn(make_random_output_value(rng)),
        TxOutputTag::CreateStakePool => {
            let pool_id = PoolId::random_using(rng);
            let pool_data = StakePoolData::new(
                Amount::from_atoms(rng.gen()),
                make_random_destination(rng),
                make_random_vrf_pub_key(rng),
                make_random_destination(rng),
                PerThousand::new(rng.gen_range(0..=1000)).unwrap(),
                Amount::from_atoms(rng.gen()),
            );
            TxOutput::CreateStakePool(pool_id, Box::new(pool_data))
        }
        TxOutputTag::ProduceBlockFromStake => {
            TxOutput::ProduceBlockFromStake(make_random_destination(rng), PoolId::random_using(rng))
        }
        TxOutputTag::CreateDelegationId => {
            TxOutput::CreateDelegationId(make_random_destination(rng), PoolId::random_using(rng))
        }
        TxOutputTag::DelegateStaking => TxOutput::DelegateStaking(
            Amount::from_atoms(rng.gen()),
            DelegationId::random_using(rng),
        ),
        TxOutputTag::IssueFungibleToken => {
            let issuance = TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: random_ascii_alphanumeric_string(rng, 3..5).into_bytes(),
                number_of_decimals: rng.gen(),
                metadata_uri: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
                total_supply: TokenTotalSupply::Fixed(Amount::from_atoms(rng.gen())),
                authority: make_random_destination(rng),
                is_freezable: IsTokenFreezable::Yes,
            });
            TxOutput::IssueFungibleToken(Box::new(issuance))
        }
        TxOutputTag::IssueNft => {
            let token_id = TokenId::random_using(rng);
            let metadata = Metadata {
                creator: Some(make_random_pub_key(rng).into()),
                name: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
                description: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
                ticker: random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
                icon_uri: Some(random_ascii_alphanumeric_string(rng, 10..20).into_bytes()).into(),
                additional_metadata_uri: Some(
                    random_ascii_alphanumeric_string(rng, 10..20).into_bytes(),
                )
                .into(),
                media_uri: Some(random_ascii_alphanumeric_string(rng, 10..20).into_bytes()).into(),
                media_hash: gen_random_bytes(rng, 10, 20),
            };
            let issuance = NftIssuance::V0(NftIssuanceV0 { metadata });
            let destination = make_random_destination(rng);
            TxOutput::IssueNft(token_id, Box::new(issuance), destination)
        }
        TxOutputTag::DataDeposit => TxOutput::DataDeposit(gen_random_bytes(rng, 10, 20)),
        TxOutputTag::Htlc => {
            let htlc = HashedTimelockContract {
                secret_hash: HtlcSecretHash::random_using(rng),
                spend_key: make_random_destination(rng),
                refund_timelock: OutputTimeLock::ForBlockCount(rng.gen()),
                refund_key: make_random_destination(rng),
            };
            TxOutput::Htlc(make_random_output_value(rng), Box::new(htlc))
        }
        TxOutputTag::CreateOrder => {
            let order_data = OrderData::new(
                make_random_destination(rng),
                make_random_output_value(rng),
                make_random_output_value(rng),
            );
            TxOutput::CreateOrder(Box::new(order_data))
        }
    }
}

pub fn generate_input_utxo(rng: &mut (impl Rng + CryptoRng)) -> TxOutput {
    let tag = TxOutputTag::iter().choose(rng).unwrap();
    generate_input_utxo_for_tag(rng, tag)
}

pub fn generate_input_commitment_for_tag(
    rng: &mut (impl Rng + CryptoRng),
    tag: SighashInputCommitmentTag,
) -> SighashInputCommitment<'static> {
    match tag {
        SighashInputCommitmentTag::None => SighashInputCommitment::None,
        SighashInputCommitmentTag::Utxo => {
            let utxo = generate_input_utxo(rng);
            SighashInputCommitment::Utxo(Cow::Owned(utxo))
        }
        SighashInputCommitmentTag::ProduceBlockFromStakeUtxo => {
            let utxo = generate_input_utxo(rng);
            let staker_balance = Amount::from_atoms(rng.gen::<UnsignedIntType>());
            SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo: Cow::Owned(utxo),
                staker_balance,
            }
        }
        SighashInputCommitmentTag::FillOrderAccountCommand => {
            let initially_asked = make_random_output_value(rng);
            let initially_given = make_random_output_value(rng);

            SighashInputCommitment::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            }
        }
        SighashInputCommitmentTag::ConcludeOrderAccountCommand => {
            let initially_asked = make_random_output_value(rng);
            let initially_given = make_random_output_value(rng);
            let ask_balance = Amount::from_atoms(rng.gen());
            let give_balance = Amount::from_atoms(rng.gen());

            SighashInputCommitment::ConcludeOrderAccountCommand {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            }
        }
    }
}

pub fn generate_input_commitment(
    rng: &mut (impl Rng + CryptoRng),
) -> SighashInputCommitment<'static> {
    let tag = SighashInputCommitmentTag::iter().choose(rng).unwrap();
    generate_input_commitment_for_tag(rng, tag)
}

pub fn generate_input_commitments(
    rng: &mut (impl Rng + CryptoRng),
    input_count: usize,
) -> Vec<SighashInputCommitment<'static>> {
    (0..input_count).map(|_| generate_input_commitment(rng)).collect()
}

pub fn generate_inputs_utxos(
    rng: &mut (impl Rng + CryptoRng),
    input_count: usize,
) -> Vec<Option<TxOutput>> {
    (0..input_count)
        .map(|_| {
            if rng.gen::<bool>() {
                Some(generate_input_utxo(rng))
            } else {
                None
            }
        })
        .collect_vec()
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

pub struct SignedTransactionWithInputCommitments {
    pub tx: SignedTransaction,
    pub input_commitments: Vec<SighashInputCommitment<'static>>,
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
    outputs_count: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
) -> Result<SignedTransaction, TransactionCreationError> {
    let tx =
        generate_unsigned_tx(rng, destination, input_commitments.len(), outputs_count).unwrap();
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

pub fn generate_signed_tx_with_input_commitments(
    chain_config: &ChainConfig,
    rng: &mut (impl Rng + CryptoRng),
    destination: &Destination,
    inputs_count: usize,
    outputs_count: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
) -> Result<SignedTransactionWithInputCommitments, TransactionCreationError> {
    let input_commitments = generate_input_commitments(rng, inputs_count);

    let tx = generate_and_sign_tx(
        chain_config,
        rng,
        destination,
        &input_commitments,
        outputs_count,
        private_key,
        sighash_type,
    )?;

    Ok(SignedTransactionWithInputCommitments {
        tx,
        input_commitments,
    })
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
