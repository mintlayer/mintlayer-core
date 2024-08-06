// Copyright (c) 2024 RBB S.r.l
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

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use common::{
    address::Address,
    chain::{
        output_value::OutputValue,
        partially_signed_transaction::PartiallySignedTransaction,
        signature::{
            inputsig::{
                arbitrary_message::ArbitraryMessageSignature,
                authorize_pubkey_spend::AuthorizedPublicKeySpend,
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                classical_multisig::{
                    authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                    multisig_partial_signature::{self, PartiallySignedMultisigChallenge},
                },
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
            DestinationSigError,
        },
        timelock::OutputTimeLock,
        tokens::{NftIssuance, TokenIssuance, TokenTotalSupply},
        AccountCommand, AccountSpending, ChainConfig, Destination, OutPointSourceId,
        SignedTransactionIntent, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, H256},
};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivable::Derivable, u31::U31},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
    Signature,
};
use itertools::Itertools;
use serialization::Encode;
use trezor_client::{
    client::mintlayer::MintlayerSignature,
    find_devices,
    protos::{
        MintlayerAccountCommandTxInput, MintlayerAccountTxInput, MintlayerAddressPath,
        MintlayerBurnTxOutput, MintlayerChangeTokenAuhtority, MintlayerChangeTokenMediaUri,
        MintlayerCreateDelegationIdTxOutput, MintlayerCreateStakePoolTxOutput,
        MintlayerDataDepositTxOutput, MintlayerDelegateStakingTxOutput, MintlayerFreezeToken,
        MintlayerIssueFungibleTokenTxOutput, MintlayerIssueNftTxOutput,
        MintlayerLockThenTransferTxOutput, MintlayerLockTokenSupply, MintlayerMintTokens,
        MintlayerOutputValue, MintlayerProduceBlockFromStakeTxOutput, MintlayerTokenTotalSupply,
        MintlayerTokenTotalSupplyType, MintlayerTxInput, MintlayerTxOutput, MintlayerUnfreezeToken,
        MintlayerUnmintTokens, MintlayerUtxoType,
    },
};
#[allow(clippy::all)]
use trezor_client::{
    protos::{MintlayerTransferTxOutput, MintlayerUtxoTxInput},
    Trezor,
};
use utils::ensure;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteUnlocked,
};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX, signature_status::SignatureStatus, AccountId,
};

use crate::{
    key_chain::{make_account_path, AccountKeyChainImplHardware, AccountKeyChains, FoundPubKey},
    Account, WalletError, WalletResult,
};

use super::{Signer, SignerError, SignerProvider, SignerResult};

/// Signer errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum TrezorError {
    #[error("No connected Trezor device found")]
    NoDeviceFound,
    #[error("Trezor device error: {0}")]
    DeviceError(#[from] trezor_client::Error),
}

pub struct TrezorSigner {
    chain_config: Arc<ChainConfig>,
    client: Arc<Mutex<Trezor>>,
}

impl TrezorSigner {
    pub fn new(chain_config: Arc<ChainConfig>, client: Arc<Mutex<Trezor>>) -> Self {
        Self {
            chain_config,
            client,
        }
    }

    fn make_signature(
        &self,
        signature: &Vec<MintlayerSignature>,
        destination: &Destination,
        sighash_type: SigHashType,
        sighash: H256,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)> {
        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKeyHash(_) => {
                if let Some(signature) = signature.first() {
                    let pk =
                        key_chain.find_public_key(destination).expect("found").into_public_key();
                    let mut signature = signature.signature.clone();
                    signature.insert(0, 0);
                    let sig = Signature::from_data(signature)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        sig.encode(),
                    ));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    Ok((None, SignatureStatus::NotSigned))
                }
            }
            Destination::PublicKey(_) => {
                if let Some(signature) = signature.first() {
                    let mut signature = signature.signature.clone();
                    signature.insert(0, 0);
                    let sig = Signature::from_data(signature)?;
                    let sig = AuthorizedPublicKeySpend::new(sig);
                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        sig.encode(),
                    ));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    Ok((None, SignatureStatus::NotSigned))
                }
            }
            Destination::ClassicMultisig(_) => {
                if let Some(challenge) = key_chain.find_multisig_challenge(destination) {
                    let mut current_signatures =
                        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

                    for sig in signature {
                        if let Some(idx) = sig.multisig_idx {
                            let mut signature = sig.signature.clone();
                            signature.insert(0, 0);
                            let sig = Signature::from_data(signature)?;
                            current_signatures.add_signature(idx as u8, sig);
                        }
                    }

                    let msg = sighash.encode();
                    // Check the signatures status again after adding that last signature
                    let verifier = PartiallySignedMultisigChallenge::from_partial(
                        &self.chain_config,
                        &msg,
                        &current_signatures,
                    )?;

                    let status = match verifier.verify_signatures(&self.chain_config)? {
                        multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
                            SignatureStatus::FullySigned
                        }
                        multisig_partial_signature::SigsVerifyResult::Incomplete => {
                            SignatureStatus::PartialMultisig {
                                required_signatures: challenge.min_required_signatures(),
                                num_signatures: current_signatures.signatures().len() as u8,
                            }
                        }
                        multisig_partial_signature::SigsVerifyResult::Invalid => {
                            unreachable!(
                                "We checked the signatures then added a signature, so this should be unreachable"
                            )
                        }
                    };

                    let sig = InputWitness::Standard(StandardInputSignature::new(
                        sighash_type,
                        current_signatures.encode(),
                    ));
                    return Ok((Some(sig), status));
                }

                Ok((None, SignatureStatus::NotSigned))
            }
            Destination::ScriptHash(_) => Ok((None, SignatureStatus::NotSigned)),
        }
    }

    fn to_trezor_output_msgs(&self, ptx: &PartiallySignedTransaction) -> Vec<MintlayerTxOutput> {
        let outputs = ptx
            .tx()
            .outputs()
            .iter()
            .map(|out| to_trezor_output_msg(&self.chain_config, out))
            .collect();
        outputs
    }
}

impl Signer for TrezorSigner {
    fn sign_tx(
        &mut self,
        ptx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
        _db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        let inputs = to_trezor_input_msgs(&ptx, key_chain, &self.chain_config)?;
        let outputs = self.to_trezor_output_msgs(&ptx);
        let utxos = to_trezor_utxo_msgs(&ptx, &self.chain_config);

        let new_signatures = self
            .client
            .lock()
            .expect("poisoned lock")
            .mintlayer_sign_tx(inputs, outputs, utxos)
            .map_err(TrezorError::DeviceError)?;

        let inputs_utxo_refs: Vec<_> =
            ptx.input_utxos().iter().map(|u| u.as_ref().map(|(x, _)| x)).collect();

        let (witnesses, prev_statuses, new_statuses) = ptx
            .witnesses()
            .iter()
            .enumerate()
            .zip(ptx.destinations())
            .map(|((i, witness), destination)| match witness {
                Some(w) => match w {
                    InputWitness::NoSignature(_) => Ok((
                        Some(w.clone()),
                        SignatureStatus::FullySigned,
                        SignatureStatus::FullySigned,
                    )),
                    InputWitness::Standard(sig) => match destination {
                        Some(destination) => {
                            let sighash =
                                signature_hash(sig.sighash_type(), ptx.tx(), &inputs_utxo_refs, i)?;

                            if sig
                                .verify_signature(&self.chain_config, destination, &sighash)
                                .is_ok()
                            {
                                Ok((
                                    Some(w.clone()),
                                    SignatureStatus::FullySigned,
                                    SignatureStatus::FullySigned,
                                ))
                            } else if let Destination::ClassicMultisig(_) = destination {
                                let mut current_signatures = AuthorizedClassicalMultisigSpend::from_data(
                                    sig.raw_signature(),
                                )?;

                                let previous_status = SignatureStatus::PartialMultisig {
                                    required_signatures: current_signatures.challenge().min_required_signatures(),
                                    num_signatures: current_signatures.signatures().len() as u8,
                                };

                                if let Some(signature) = new_signatures.get(i) {
                                for sig in signature {
                                    if let Some(idx) = sig.multisig_idx {
                                        let mut signature = sig.signature.clone();
                                        signature.insert(0, 0);
                                        let sig = Signature::from_data(signature)?;
                                        current_signatures.add_signature(idx as u8, sig);
                                    }
                                }

                                let msg = sighash.encode();
                                // Check the signatures status again after adding that last signature
                                let verifier = PartiallySignedMultisigChallenge::from_partial(
                                    &self.chain_config,
                                    &msg,
                                    &current_signatures,
                                )?;

                                let status = match verifier.verify_signatures(&self.chain_config)? {
                                    multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
                                        SignatureStatus::FullySigned
                                    }
                                    multisig_partial_signature::SigsVerifyResult::Incomplete => {
                                        let challenge = current_signatures.challenge();
                                        SignatureStatus::PartialMultisig {
                                            required_signatures: challenge.min_required_signatures(),
                                            num_signatures: current_signatures.signatures().len() as u8,
                                        }
                                    }
                                    multisig_partial_signature::SigsVerifyResult::Invalid => {
                                        unreachable!(
                                            "We checked the signatures then added a signature, so this should be unreachable"
                                        )
                                    }
                                };

                                let sighash_type =
                                    SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
                                let sig = InputWitness::Standard(StandardInputSignature::new(
                                    sighash_type,
                                    current_signatures.encode(),
                                ));
                                return Ok((Some(sig),
                                        previous_status,
                                        status));
                                }
                                else {
                                Ok((
                                    None,
                                    SignatureStatus::InvalidSignature,
                                    SignatureStatus::NotSigned,
                                ))

                                }


                            } else {
                                Ok((
                                    None,
                                    SignatureStatus::InvalidSignature,
                                    SignatureStatus::NotSigned,
                                ))
                            }
                        }
                        None => Ok((
                            Some(w.clone()),
                            SignatureStatus::UnknownSignature,
                            SignatureStatus::UnknownSignature,
                        )),
                    },
                },
                None => match (destination, new_signatures.get(i)) {
                    (Some(destination), Some(sig)) => {
                        let sighash_type =
                            SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
                        let sighash = signature_hash(sighash_type, ptx.tx(), &inputs_utxo_refs, i)?;
                        let (sig, status) = self.make_signature(
                            sig,
                            destination,
                            sighash_type,
                            sighash,
                            key_chain,
                        )?;
                        Ok((sig, SignatureStatus::NotSigned, status))
                    }
                    (Some(_) | None, None) | (None, Some(_)) => {
                        Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned))
                    }
                },
            })
            .collect::<Result<Vec<_>, SignerError>>()?
            .into_iter()
            .multiunzip();

        Ok((ptx.with_witnesses(witnesses), prev_statuses, new_statuses))
    }

    fn sign_challenge(
        &mut self,
        message: &[u8],
        destination: &Destination,
        key_chain: &impl AccountKeyChains,
        _db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<ArbitraryMessageSignature> {
        let data = match key_chain.find_public_key(destination) {
            Some(FoundPubKey::Hierarchy(xpub)) => {
                let address_n = xpub
                    .get_derivation_path()
                    .as_slice()
                    .iter()
                    .map(|c| c.into_encoded_index())
                    .collect();

                let addr = Address::new(&self.chain_config, destination.clone())
                    .expect("addressable")
                    .into_string();

                let sig = self
                    .client
                    .lock()
                    .expect("poisoned lock")
                    .mintlayer_sign_message(address_n, addr, message.to_vec())
                    .map_err(TrezorError::DeviceError)?;
                let mut signature = sig;
                signature.insert(0, 0);
                let signature = Signature::from_data(signature)?;

                match &destination {
                    Destination::PublicKey(_) => AuthorizedPublicKeySpend::new(signature).encode(),
                    Destination::PublicKeyHash(_) => {
                        AuthorizedPublicKeyHashSpend::new(xpub.into_public_key(), signature)
                            .encode()
                    }
                    Destination::AnyoneCanSpend => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend,
                        ))
                    }
                    Destination::ClassicMultisig(_) => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
                        ))
                    }
                    Destination::ScriptHash(_) => {
                        return Err(SignerError::SigningError(
                            DestinationSigError::Unsupported,
                        ))
                    }
                }
            }
            Some(FoundPubKey::Standalone(_)) => {
                unimplemented!("standalone keys with trezor")
            }
            None => return Err(SignerError::DestinationNotFromThisWallet),
        };

        let sig = ArbitraryMessageSignature::from_data(data);
        Ok(sig)
    }

    fn sign_transaction_intent(
        &mut self,
        _transaction: &Transaction,
        _input_destinations: &[Destination],
        _intent: &str,
        _key_chain: &impl AccountKeyChains,
        _db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<SignedTransactionIntent> {
        unimplemented!("FIXME")
    }
}

fn tx_output_value(out: &TxOutput) -> OutputValue {
    match out {
        TxOutput::Transfer(value, _)
        | TxOutput::Htlc(value, _)
        | TxOutput::LockThenTransfer(value, _, _)
        | TxOutput::Burn(value) => value.clone(),
        TxOutput::DelegateStaking(amount, _) => OutputValue::Coin(*amount),
        TxOutput::IssueNft(token_id, _, _) => {
            OutputValue::TokenV1(*token_id, Amount::from_atoms(1))
        }
        TxOutput::CreateStakePool(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::CreateOrder(_)
        | TxOutput::DataDeposit(_) => OutputValue::Coin(Amount::ZERO),
    }
}

fn to_trezor_input_msgs(
    ptx: &PartiallySignedTransaction,
    key_chain: &impl AccountKeyChains,
    chain_config: &ChainConfig,
) -> SignerResult<Vec<MintlayerTxInput>> {
    ptx.tx()
        .inputs()
        .iter()
        .zip(ptx.input_utxos())
        .zip(ptx.destinations())
        .map(|((inp, utxo), dest)| match (inp, utxo, dest) {
            (TxInput::Utxo(outpoint), Some(utxo), Some(dest)) => Ok(to_trezor_utxo_input(
                outpoint,
                &utxo.0,
                chain_config,
                dest,
                key_chain,
            )),
            (TxInput::Account(outpoint), _, Some(dest)) => Ok(to_trezor_account_input(
                chain_config,
                dest,
                key_chain,
                outpoint,
            )),
            (TxInput::AccountCommand(nonce, command), _, Some(dest)) => Ok(
                to_trezor_account_command_input(chain_config, dest, key_chain, nonce, command),
            ),
            (_, _, None) => Err(SignerError::MissingDestinationInTransaction),
            (TxInput::Utxo(_), _, _) => Err(SignerError::MissingUtxo),
        })
        .collect()
}

fn to_trezor_account_command_input(
    chain_config: &ChainConfig,
    dest: &Destination,
    key_chain: &impl AccountKeyChains,
    nonce: &common::chain::AccountNonce,
    command: &AccountCommand,
) -> MintlayerTxInput {
    let mut inp_req = MintlayerAccountCommandTxInput::new();
    inp_req
        .set_address(Address::new(chain_config, dest.clone()).expect("addressable").into_string());
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            inp_req.address_n = vec![MintlayerAddressPath {
                address_n,
                ..Default::default()
            }];
        }
        Some(FoundPubKey::Standalone(_)) => {
            unimplemented!("standalone keys with trezor")
        }
        None => {}
    };
    inp_req.set_nonce(nonce.value());
    match command {
        AccountCommand::MintTokens(token_id, amount) => {
            let mut req = MintlayerMintTokens::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            req.set_amount(amount.into_atoms().to_be_bytes().to_vec());

            inp_req.mint = Some(req).into();
        }
        AccountCommand::UnmintTokens(token_id) => {
            let mut req = MintlayerUnmintTokens::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());

            inp_req.unmint = Some(req).into();
        }
        AccountCommand::FreezeToken(token_id, unfreezable) => {
            let mut req = MintlayerFreezeToken::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            req.set_is_token_unfreezabe(unfreezable.as_bool());

            inp_req.freeze_token = Some(req).into();
        }
        AccountCommand::UnfreezeToken(token_id) => {
            let mut req = MintlayerUnfreezeToken::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());

            inp_req.unfreeze_token = Some(req).into();
        }
        AccountCommand::LockTokenSupply(token_id) => {
            let mut req = MintlayerLockTokenSupply::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());

            inp_req.lock_token_supply = Some(req).into();
        }
        AccountCommand::ChangeTokenAuthority(token_id, dest) => {
            let mut req = MintlayerChangeTokenAuhtority::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );

            inp_req.change_token_authority = Some(req).into();
        }
        AccountCommand::ChangeTokenMetadataUri(token_id, uri) => {
            let mut req = MintlayerChangeTokenMediaUri::new();
            req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            req.set_media_uri(uri.clone());

            inp_req.change_token_metadata_uri = Some(req).into();
        }
        AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {
            unimplemented!("order commands")
        }
        AccountCommand::ChangeTokenMetadataUri(_, _) => unimplemented!("FIXME"),
    }
    let mut inp = MintlayerTxInput::new();
    inp.account_command = Some(inp_req).into();
    inp
}

fn to_trezor_account_input(
    chain_config: &ChainConfig,
    dest: &Destination,
    key_chain: &impl AccountKeyChains,
    outpoint: &common::chain::AccountOutPoint,
) -> MintlayerTxInput {
    let mut inp_req = MintlayerAccountTxInput::new();
    inp_req
        .set_address(Address::new(chain_config, dest.clone()).expect("addressable").into_string());
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            inp_req.address_n = vec![MintlayerAddressPath {
                address_n,
                ..Default::default()
            }];
        }
        Some(FoundPubKey::Standalone(_)) => {
            unimplemented!("standalone keys with trezor")
        }
        None => {}
    };
    inp_req.set_nonce(outpoint.nonce().value());
    match outpoint.account() {
        AccountSpending::DelegationBalance(delegation_id, amount) => {
            inp_req.set_delegation_id(delegation_id.to_hash().as_bytes().to_vec());
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            inp_req.value = Some(value).into();
        }
    }
    let mut inp = MintlayerTxInput::new();
    inp.account = Some(inp_req).into();
    inp
}

fn to_trezor_utxo_input(
    outpoint: &common::chain::UtxoOutPoint,
    utxo: &TxOutput,
    chain_config: &ChainConfig,
    dest: &Destination,
    key_chain: &impl AccountKeyChains,
) -> MintlayerTxInput {
    let mut inp_req = MintlayerUtxoTxInput::new();
    let id = match outpoint.source_id() {
        OutPointSourceId::Transaction(id) => {
            inp_req.set_type(MintlayerUtxoType::TRANSACTION);
            id.to_hash().0
        }
        OutPointSourceId::BlockReward(id) => {
            inp_req.set_type(MintlayerUtxoType::BLOCK);
            id.to_hash().0
        }
    };
    inp_req.set_prev_hash(id.to_vec());
    inp_req.set_prev_index(outpoint.output_index());
    match tx_output_value(utxo) {
        OutputValue::Coin(amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            inp_req.value = Some(value).into();
        }
        OutputValue::TokenV1(token_id, amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            value.set_token_id(token_id.to_hash().as_bytes().to_vec());
            inp_req.value = Some(value).into();
        }
        OutputValue::TokenV0(_) => {
            panic!("token v0 unsuported");
        }
    }

    inp_req
        .set_address(Address::new(chain_config, dest.clone()).expect("addressable").into_string());
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            inp_req.address_n = vec![MintlayerAddressPath {
                address_n,
                ..Default::default()
            }];
        }
        Some(FoundPubKey::Standalone(_)) => {
            unimplemented!("standalone keys with trezor")
        }
        None => {
            if let Some(challenge) = key_chain.find_multisig_challenge(dest) {
                inp_req.address_n = challenge
                    .public_keys()
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, pk)| {
                        match key_chain.find_public_key(&Destination::PublicKey(pk.clone())) {
                            Some(FoundPubKey::Hierarchy(xpub)) => {
                                let address_n = xpub
                                    .get_derivation_path()
                                    .as_slice()
                                    .iter()
                                    .map(|c| c.into_encoded_index())
                                    .collect();
                                Some(MintlayerAddressPath {
                                    address_n,
                                    multisig_idx: Some(idx as u32),
                                    special_fields: Default::default(),
                                })
                            }
                            Some(FoundPubKey::Standalone(_)) => unimplemented!("standalone keys"),
                            None => None,
                        }
                    })
                    .collect();
            }
        }
    };

    let mut inp = MintlayerTxInput::new();
    inp.utxo = Some(inp_req).into();
    inp
}

fn to_trezor_utxo_msgs(
    ptx: &PartiallySignedTransaction,
    chain_config: &ChainConfig,
) -> BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTxOutput>> {
    let utxos = ptx.input_utxos().iter().zip(ptx.tx().inputs()).fold(
        BTreeMap::new(),
        |mut map: BTreeMap<[u8; 32], BTreeMap<u32, _>>, (utxo, inp)| {
            match (inp, utxo) {
                (TxInput::Utxo(outpoint), Some(utxo)) => {
                    let id = match outpoint.source_id() {
                        OutPointSourceId::Transaction(id) => id.to_hash().0,
                        OutPointSourceId::BlockReward(id) => id.to_hash().0,
                    };
                    let out = to_trezor_output_msg(chain_config, &utxo.0);
                    map.entry(id).or_default().insert(outpoint.output_index(), out);
                }
                (TxInput::Utxo(_), None) => unimplemented!("missing utxo"),
                (TxInput::Account(_) | TxInput::AccountCommand(_, _), Some(_)) => {
                    panic!("can't have accounts as UTXOs")
                }
                (TxInput::Account(_) | TxInput::AccountCommand(_, _), _) => {}
            }
            map
        },
    );
    utxos
}

fn set_value(value: &OutputValue, out_req: &mut MintlayerTransferTxOutput) {
    match value {
        OutputValue::Coin(amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            out_req.value = Some(value).into();
        }
        OutputValue::TokenV1(token_id, amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            value.set_token_id(token_id.to_hash().as_bytes().to_vec());
            out_req.value = Some(value).into();
        }
        OutputValue::TokenV0(_) => {
            panic!("token v0 unsuported");
        }
    };
}

fn to_trezor_output_msg(chain_config: &ChainConfig, out: &TxOutput) -> MintlayerTxOutput {
    match out {
        TxOutput::Transfer(value, dest) => {
            let mut out_req = MintlayerTransferTxOutput::new();
            set_value(value, &mut out_req);
            out_req.set_address(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );

            let mut out = MintlayerTxOutput::new();
            out.transfer = Some(out_req).into();
            out
        }
        TxOutput::LockThenTransfer(value, dest, lock) => {
            let mut out_req = MintlayerLockThenTransferTxOutput::new();
            match value {
                OutputValue::Coin(amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV1(token_id, amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    value.set_token_id(token_id.to_hash().as_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV0(_) => {
                    panic!("token v0 unsuported");
                }
            };
            out_req.set_address(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );

            let mut lock_req = trezor_client::protos::MintlayerOutputTimeLock::new();
            match lock {
                OutputTimeLock::UntilTime(time) => {
                    lock_req.set_until_time(time.as_int_seconds());
                }
                OutputTimeLock::UntilHeight(height) => {
                    lock_req.set_until_height(height.into_int());
                }
                OutputTimeLock::ForSeconds(sec) => {
                    lock_req.set_for_seconds(*sec);
                }
                OutputTimeLock::ForBlockCount(count) => {
                    lock_req.set_for_block_count(*count);
                }
            }
            out_req.lock = Some(lock_req).into();

            let mut out = MintlayerTxOutput::new();
            out.lock_then_transfer = Some(out_req).into();
            out
        }
        TxOutput::Burn(value) => {
            let mut out_req = MintlayerBurnTxOutput::new();
            match value {
                OutputValue::Coin(amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV1(token_id, amount) => {
                    let mut value = MintlayerOutputValue::new();
                    value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
                    value.set_token_id(token_id.to_hash().as_bytes().to_vec());
                    out_req.value = Some(value).into();
                }
                OutputValue::TokenV0(_) => {
                    panic!("token v0 unsuported");
                }
            };

            let mut out = MintlayerTxOutput::new();
            out.burn = Some(out_req).into();
            out
        }
        TxOutput::CreateDelegationId(dest, pool_id) => {
            let mut out_req = MintlayerCreateDelegationIdTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            let mut out = MintlayerTxOutput::new();
            out.create_delegation_id = Some(out_req).into();
            out
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            let mut out_req = MintlayerDelegateStakingTxOutput::new();
            out_req.set_delegation_id(delegation_id.to_hash().as_bytes().to_vec());
            out_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            let mut out = MintlayerTxOutput::new();
            out.delegate_staking = Some(out_req).into();
            out
        }
        TxOutput::CreateStakePool(pool_id, pool_data) => {
            let mut out_req = MintlayerCreateStakePoolTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());

            out_req.set_pledge(pool_data.pledge().into_atoms().to_be_bytes().to_vec());
            out_req.set_staker(
                Address::new(chain_config, pool_data.staker().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req.set_decommission_key(
                Address::new(chain_config, pool_data.decommission_key().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req.set_vrf_public_key(
                Address::new(chain_config, pool_data.vrf_public_key().clone())
                    .expect("addressable")
                    .into_string(),
            );
            out_req
                .set_cost_per_block(pool_data.cost_per_block().into_atoms().to_be_bytes().to_vec());
            out_req.set_margin_ratio_per_thousand(
                pool_data.margin_ratio_per_thousand().as_per_thousand_int() as u32,
            );

            let mut out = MintlayerTxOutput::new();
            out.create_stake_pool = Some(out_req).into();
            out
        }
        TxOutput::ProduceBlockFromStake(dest, pool_id) => {
            let mut out_req = MintlayerProduceBlockFromStakeTxOutput::new();
            out_req.set_pool_id(pool_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            let mut out = MintlayerTxOutput::new();
            out.produce_block_from_stake = Some(out_req).into();
            out
        }
        TxOutput::IssueFungibleToken(token_data) => {
            let mut out_req = MintlayerIssueFungibleTokenTxOutput::new();

            match token_data.as_ref() {
                TokenIssuance::V1(data) => {
                    out_req.set_authority(
                        Address::new(chain_config, data.authority.clone())
                            .expect("addressable")
                            .into_string(),
                    );
                    out_req.set_token_ticker(data.token_ticker.clone());
                    out_req.set_metadata_uri(data.metadata_uri.clone());
                    out_req.set_number_of_decimals(data.number_of_decimals as u32);
                    out_req.set_is_freezable(data.is_freezable.as_bool());
                    let mut total_supply = MintlayerTokenTotalSupply::new();
                    match data.total_supply {
                        TokenTotalSupply::Lockable => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::LOCKABLE)
                        }
                        TokenTotalSupply::Unlimited => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::UNLIMITED)
                        }
                        TokenTotalSupply::Fixed(amount) => {
                            total_supply.set_type(MintlayerTokenTotalSupplyType::FIXED);
                            total_supply
                                .set_fixed_amount(amount.into_atoms().to_be_bytes().to_vec());
                        }
                    }
                    out_req.total_supply = Some(total_supply).into();
                }
            };

            let mut out = MintlayerTxOutput::new();
            out.issue_fungible_token = Some(out_req).into();
            out
        }
        TxOutput::IssueNft(token_id, nft_data, dest) => {
            let mut out_req = MintlayerIssueNftTxOutput::new();
            out_req.set_token_id(token_id.to_hash().as_bytes().to_vec());
            out_req.set_destination(
                Address::new(chain_config, dest.clone()).expect("addressable").into_string(),
            );
            match nft_data.as_ref() {
                NftIssuance::V0(data) => {
                    //
                    out_req.set_name(data.metadata.name.clone());
                    out_req.set_ticker(data.metadata.ticker().clone());
                    out_req.set_icon_uri(
                        data.metadata.icon_uri().as_ref().clone().unwrap_or_default(),
                    );
                    out_req.set_media_uri(
                        data.metadata.media_uri().as_ref().clone().unwrap_or_default(),
                    );
                    out_req.set_media_hash(data.metadata.media_hash().clone());
                    out_req.set_additional_metadata_uri(
                        data.metadata
                            .additional_metadata_uri()
                            .as_ref()
                            .clone()
                            .unwrap_or_default(),
                    );
                    out_req.set_description(data.metadata.description.clone());
                    if let Some(creator) = data.metadata.creator() {
                        out_req.set_creator(
                            Address::new(
                                chain_config,
                                Destination::PublicKey(creator.public_key.clone()),
                            )
                            .expect("addressable")
                            .into_string(),
                        );
                    }
                }
            };
            let mut out = MintlayerTxOutput::new();
            out.issue_nft = Some(out_req).into();
            out
        }
        TxOutput::DataDeposit(data) => {
            let mut out_req = MintlayerDataDepositTxOutput::new();
            out_req.set_data(data.clone());
            let mut out = MintlayerTxOutput::new();
            out.data_deposit = Some(out_req).into();
            out
        }
        TxOutput::Htlc(_, _) => unimplemented!("HTLC"),
        TxOutput::CreateOrder(_) => unimplemented!("CreateOrder"),
    }
}

#[derive(Clone)]
pub struct TrezorSignerProvider {
    client: Arc<Mutex<Trezor>>,
}

impl std::fmt::Debug for TrezorSignerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrezorSignerProvider")
    }
}

impl TrezorSignerProvider {
    pub fn new() -> Result<Self, TrezorError> {
        let client = find_trezor_device()?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
    ) -> WalletResult<Self> {
        let client = find_trezor_device().map_err(SignerError::TrezorError)?;

        let provider = Self {
            client: Arc::new(Mutex::new(client)),
        };

        check_public_keys(db_tx, &provider, chain_config)?;

        Ok(provider)
    }

    fn fetch_extended_pub_key(
        &self,
        chain_config: &Arc<ChainConfig>,
        account_index: U31,
    ) -> Result<ExtendedPublicKey, WalletError> {
        let derivation_path = make_account_path(chain_config, account_index);
        let account_path =
            derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect();
        let xpub = self
            .client
            .lock()
            .expect("poisoned lock")
            .mintlayer_get_public_key(account_path)
            .map_err(|e| SignerError::TrezorError(TrezorError::DeviceError(e)))?;
        let chain_code = ChainCode::from(xpub.chain_code.0);
        let account_pubkey = Secp256k1ExtendedPublicKey::from_hardware_wallet(
            derivation_path,
            chain_code,
            Secp256k1PublicKey::from_bytes(&xpub.public_key.serialize()).expect(""),
        );
        let account_pubkey = ExtendedPublicKey::from_hardware_public_key(account_pubkey);
        Ok(account_pubkey)
    }
}

/// Check that the public keys in the DB are the same as the ones with the connected hardware
/// wallet
fn check_public_keys(
    db_tx: &impl WalletStorageReadLocked,
    provider: &TrezorSignerProvider,
    chain_config: Arc<ChainConfig>,
) -> Result<(), WalletError> {
    let first_acc = db_tx
        .get_accounts_info()?
        .iter()
        .find_map(|(acc_id, info)| {
            (info.account_index() == DEFAULT_ACCOUNT_INDEX).then_some(acc_id)
        })
        .cloned()
        .ok_or(WalletError::WalletNotInitialized)?;
    let expected_pk = provider.fetch_extended_pub_key(&chain_config, DEFAULT_ACCOUNT_INDEX)?;
    let loaded_acc = provider.load_account_from_database(chain_config, db_tx, &first_acc)?;
    ensure!(
        loaded_acc.key_chain().account_public_key() == &expected_pk,
        WalletError::HardwareWalletDifferentFile
    );
    Ok(())
}

fn find_trezor_device() -> Result<Trezor, TrezorError> {
    let mut devices = find_devices(false);
    let device = devices.pop().ok_or(TrezorError::NoDeviceFound)?;
    let client = device.connect()?;
    Ok(client)
}

impl SignerProvider for TrezorSignerProvider {
    type S = TrezorSigner;
    type K = AccountKeyChainImplHardware;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, _account_index: U31) -> Self::S {
        TrezorSigner::new(chain_config, self.client.clone())
    }

    fn make_new_account(
        &mut self,
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        name: Option<String>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
    ) -> WalletResult<Account<Self::K>> {
        let account_pubkey = self.fetch_extended_pub_key(&chain_config, account_index)?;

        let lookahead_size = db_tx.get_lookahead_size()?;

        let key_chain = AccountKeyChainImplHardware::new_from_hardware_key(
            chain_config.clone(),
            db_tx,
            account_pubkey,
            account_index,
            lookahead_size,
        )?;

        Account::new(chain_config, db_tx, key_chain, name)
    }

    fn load_account_from_database(
        &self,
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> WalletResult<Account<Self::K>> {
        Account::load_from_database(chain_config, db_tx, id)
    }
}

#[cfg(feature = "trezor-emulator")]
#[cfg(test)]
mod tests;
