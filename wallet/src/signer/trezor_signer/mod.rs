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
        config::ChainType,
        htlc::HtlcSecret,
        output_value::OutputValue,
        signature::{
            inputsig::{
                arbitrary_message::ArbitraryMessageSignature,
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
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
        tokens::{NftIssuance, TokenId, TokenIssuance, TokenTotalSupply},
        AccountCommand, AccountSpending, ChainConfig, Destination, OutPointSourceId,
        SignedTransactionIntent, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Idable, H256},
};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivable::Derivable, u31::U31},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
    Signature, SignatureError,
};
use itertools::Itertools;
use serialization::Encode;
use trezor_client::{
    client::mintlayer::MintlayerSignature,
    find_devices,
    protos::{
        features::Capability,
        mintlayer_tx_ack::{MintlayerTxInput, MintlayerTxOutput},
        MintlayerAccountCommandTxInput, MintlayerAccountSpendingDelegationBalance,
        MintlayerAccountTxInput, MintlayerAddressPath, MintlayerAddressType, MintlayerBurnTxOutput,
        MintlayerChainType, MintlayerChangeTokenAuthority, MintlayerChangeTokenMetadataUri,
        MintlayerConcludeOrder, MintlayerCreateDelegationIdTxOutput, MintlayerCreateOrderTxOutput,
        MintlayerCreateStakePoolTxOutput, MintlayerDataDepositTxOutput,
        MintlayerDelegateStakingTxOutput, MintlayerFillOrder, MintlayerFreezeToken,
        MintlayerHtlcTxOutput, MintlayerIssueFungibleTokenTxOutput, MintlayerIssueNftTxOutput,
        MintlayerLockThenTransferTxOutput, MintlayerLockTokenSupply, MintlayerMintTokens,
        MintlayerOutputValue, MintlayerProduceBlockFromStakeTxOutput, MintlayerTokenOutputValue,
        MintlayerTokenTotalSupply, MintlayerTokenTotalSupplyType, MintlayerUnfreezeToken,
        MintlayerUnmintTokens, MintlayerUtxoType,
    },
    Model,
};
use trezor_client::{
    protos::{MintlayerTransferTxOutput, MintlayerUtxoTxInput},
    Trezor,
};
use utils::ensure;
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteUnlocked,
};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    hw_data::{HardwareWalletData, TrezorData},
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, TokenAdditionalInfo, TxAdditionalInfo,
    },
    signature_status::SignatureStatus,
    AccountId,
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
    #[error("There are multiple connected Trezor devices found")]
    NoUniqueDeviceFound,
    #[error("Cannot get the supported features for the connected Trezor device")]
    CannotGetDeviceFeatures,
    #[error("The connected Trezor device does not support the Mintlayer capabilities, please install the correct firmware")]
    MintlayerFeaturesNotSupported,
    #[error("Trezor device error: {0}")]
    DeviceError(String),
    #[error("Invalid public key returned from trezor")]
    InvalidKey,
    #[error("Invalid Signature error: {0}")]
    SignatureError(#[from] SignatureError),
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
        signature: &[MintlayerSignature],
        destination: &Destination,
        sighash_type: SigHashType,
        sighash: H256,
        secret: Option<HtlcSecret>,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)> {
        let add_secret_if_needed = |sig: StandardInputSignature| {
            let sig = if let Some(htlc_secret) = secret {
                let sig_with_secret = AuthorizedHashedTimelockContractSpend::Secret(
                    htlc_secret,
                    sig.raw_signature().to_owned(),
                );
                let serialized_sig = sig_with_secret.encode();

                StandardInputSignature::new(sig.sighash_type(), serialized_sig)
            } else {
                sig
            };

            InputWitness::Standard(sig)
        };

        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKeyHash(_) => {
                if let Some(signature) = signature.first() {
                    let pk = key_chain
                        .find_public_key(destination)
                        .ok_or(SignerError::DestinationNotFromThisWallet)?
                        .into_public_key();
                    let sig = Signature::from_raw_data(&signature.signature)
                        .map_err(TrezorError::SignatureError)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    let sig = add_secret_if_needed(StandardInputSignature::new(
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
                    let sig = Signature::from_raw_data(&signature.signature)
                        .map_err(TrezorError::SignatureError)?;
                    let sig = AuthorizedPublicKeySpend::new(sig);
                    let sig = add_secret_if_needed(StandardInputSignature::new(
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
                            let sig = Signature::from_raw_data(&sig.signature)
                                .map_err(TrezorError::SignatureError)?;
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

                    let sig = add_secret_if_needed(StandardInputSignature::new(
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

    fn to_trezor_output_msgs(
        &self,
        ptx: &PartiallySignedTransaction,
    ) -> SignerResult<Vec<MintlayerTxOutput>> {
        let outputs = ptx
            .tx()
            .outputs()
            .iter()
            .map(|out| to_trezor_output_msg(&self.chain_config, out, ptx.additional_infos()))
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
        let outputs = self.to_trezor_output_msgs(&ptx)?;
        let utxos = to_trezor_utxo_msgs(&ptx, &self.chain_config)?;
        let chain_type = to_trezor_chain_type(&self.chain_config);

        let new_signatures = self
            .client
            .lock()
            .expect("poisoned lock")
            .mintlayer_sign_tx(chain_type, inputs, outputs, utxos)
            .map_err(|err| TrezorError::DeviceError(err.to_string()))?;

        let inputs_utxo_refs: Vec<_> = ptx.input_utxos().iter().map(|u| u.as_ref()).collect();

        let (witnesses, prev_statuses, new_statuses) = ptx
            .witnesses()
            .iter()
            .enumerate()
            .zip(ptx.destinations())
            .zip(ptx.htlc_secrets())
            .map(|(((i, witness), destination), secret)| match witness {
                Some(w) => match w {
                    InputWitness::NoSignature(_) => Ok((
                        Some(w.clone()),
                        SignatureStatus::FullySigned,
                        SignatureStatus::FullySigned,
                    )),
                    InputWitness::Standard(sig) => match destination {
                        Some(destination) => {
                            if tx_verifier::input_check::signature_only_check::verify_tx_signature(
                                &self.chain_config,
                                destination,
                                &ptx,
                                &inputs_utxo_refs,
                                i,
                            ).is_ok()
                            {
                                Ok((
                                    Some(w.clone()),
                                    SignatureStatus::FullySigned,
                                    SignatureStatus::FullySigned,
                                ))
                            } else if let Destination::ClassicMultisig(_) = destination {
                                let sighash =
                                    signature_hash(sig.sighash_type(), ptx.tx(), &inputs_utxo_refs, i)?;

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
                                        let sig = Signature::from_raw_data(&sig.signature)
                                            .map_err(TrezorError::SignatureError)?;
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
                            secret.clone(),
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

                let addr_type = match destination {
                    Destination::PublicKey(_) => MintlayerAddressType::PUBLIC_KEY,
                    Destination::PublicKeyHash(_) => MintlayerAddressType::PUBLIC_KEY_HASH,
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
                };

                let chain_type = to_trezor_chain_type(&self.chain_config);

                let sig = self
                    .client
                    .lock()
                    .expect("poisoned lock")
                    .mintlayer_sign_message(chain_type, address_n, addr_type, message.to_vec())
                    .map_err(|err| TrezorError::DeviceError(err.to_string()))?;
                let signature =
                    Signature::from_raw_data(&sig).map_err(TrezorError::SignatureError)?;

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
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent: &str,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<SignedTransactionIntent> {
        let tx_id = transaction.get_id();
        let message_to_sign = SignedTransactionIntent::get_message_to_sign(intent, &tx_id);

        let mut signatures = Vec::with_capacity(input_destinations.len());
        for dest in input_destinations {
            let sig = self.sign_challenge(message_to_sign.as_bytes(), dest, key_chain, db_tx)?;
            signatures.push(sig.into_raw());
        }

        Ok(SignedTransactionIntent::new_unchecked(
            message_to_sign,
            signatures,
        ))
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
            (TxInput::Utxo(outpoint), Some(_), Some(dest)) => {
                to_trezor_utxo_input(outpoint, dest, key_chain)
            }
            (TxInput::Account(outpoint), _, Some(dest)) => {
                to_trezor_account_input(chain_config, dest, key_chain, outpoint)
            }
            (TxInput::AccountCommand(nonce, command), _, Some(dest)) => {
                to_trezor_account_command_input(
                    chain_config,
                    dest,
                    key_chain,
                    nonce,
                    command,
                    ptx.additional_infos(),
                )
            }
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
    additional_info: &TxAdditionalInfo,
) -> SignerResult<MintlayerTxInput> {
    let mut inp_req = MintlayerAccountCommandTxInput::new();
    inp_req.addresses = destination_to_address_paths(key_chain, dest);
    inp_req.set_nonce(nonce.value());
    match command {
        AccountCommand::MintTokens(token_id, amount) => {
            let mut req = MintlayerMintTokens::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            req.set_amount(amount.into_atoms().to_be_bytes().to_vec());

            inp_req.mint = Some(req).into();
        }
        AccountCommand::UnmintTokens(token_id) => {
            let mut req = MintlayerUnmintTokens::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());

            inp_req.unmint = Some(req).into();
        }
        AccountCommand::FreezeToken(token_id, unfreezable) => {
            let mut req = MintlayerFreezeToken::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            req.set_is_token_unfreezeable(unfreezable.as_bool());

            inp_req.freeze_token = Some(req).into();
        }
        AccountCommand::UnfreezeToken(token_id) => {
            let mut req = MintlayerUnfreezeToken::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());

            inp_req.unfreeze_token = Some(req).into();
        }
        AccountCommand::LockTokenSupply(token_id) => {
            let mut req = MintlayerLockTokenSupply::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());

            inp_req.lock_token_supply = Some(req).into();
        }
        AccountCommand::ChangeTokenAuthority(token_id, dest) => {
            let mut req = MintlayerChangeTokenAuthority::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            req.set_destination(Address::new(chain_config, dest.clone())?.into_string());

            inp_req.change_token_authority = Some(req).into();
        }
        AccountCommand::ChangeTokenMetadataUri(token_id, uri) => {
            let mut req = MintlayerChangeTokenMetadataUri::new();
            req.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            req.set_metadata_uri(uri.clone());

            inp_req.change_token_metadata_uri = Some(req).into();
        }
        AccountCommand::ConcludeOrder(order_id) => {
            let mut req = MintlayerConcludeOrder::new();
            req.set_order_id(Address::new(chain_config, *order_id)?.into_string());

            let OrderAdditionalInfo {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } = additional_info
                .get_order_info(order_id)
                .ok_or(SignerError::MissingTxExtraInfo)?;

            let filled_value = match initially_asked {
                OutputValue::Coin(amount) => OutputValue::Coin(
                    (*amount - *ask_balance).ok_or(SignerError::OrderFillUnderflow)?,
                ),
                OutputValue::TokenV1(id, amount) => OutputValue::TokenV1(
                    *id,
                    (*amount - *ask_balance).ok_or(SignerError::OrderFillUnderflow)?,
                ),
                OutputValue::TokenV0(_) => return Err(SignerError::UnsupportedTokensV0),
            };
            let give_value = value_with_new_amount(initially_given, give_balance)?;

            req.filled_ask_amount = Some(to_trezor_output_value(
                &filled_value,
                additional_info,
                chain_config,
            )?)
            .into();

            req.give_balance = Some(to_trezor_output_value(
                &give_value,
                additional_info,
                chain_config,
            )?)
            .into();

            inp_req.conclude_order = Some(req).into();
        }
        AccountCommand::FillOrder(order_id, amount, dest) => {
            let mut req = MintlayerFillOrder::new();
            req.set_order_id(Address::new(chain_config, *order_id)?.into_string());
            req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            req.set_destination(Address::new(chain_config, dest.clone())?.into_string());

            let OrderAdditionalInfo {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } = additional_info
                .get_order_info(order_id)
                .ok_or(SignerError::MissingTxExtraInfo)?;

            let ask_value = value_with_new_amount(initially_asked, ask_balance)?;
            let give_value = value_with_new_amount(initially_given, give_balance)?;

            req.ask_balance = Some(to_trezor_output_value(
                &ask_value,
                additional_info,
                chain_config,
            )?)
            .into();

            req.give_balance = Some(to_trezor_output_value(
                &give_value,
                additional_info,
                chain_config,
            )?)
            .into();

            inp_req.fill_order = Some(req).into();
        }
    }
    let mut inp = MintlayerTxInput::new();
    inp.account_command = Some(inp_req).into();
    Ok(inp)
}

/// Construct a new OutputValue with a new amount
fn value_with_new_amount(
    initially_value: &OutputValue,
    new_amount: &Amount,
) -> Result<OutputValue, SignerError> {
    match initially_value {
        OutputValue::Coin(_) => Ok(OutputValue::Coin(*new_amount)),
        OutputValue::TokenV1(id, _) => Ok(OutputValue::TokenV1(*id, *new_amount)),
        OutputValue::TokenV0(_) => Err(SignerError::UnsupportedTokensV0),
    }
}

fn to_trezor_account_input(
    chain_config: &ChainConfig,
    dest: &Destination,
    key_chain: &impl AccountKeyChains,
    outpoint: &common::chain::AccountOutPoint,
) -> SignerResult<MintlayerTxInput> {
    let mut inp_req = MintlayerAccountTxInput::new();
    inp_req.addresses = destination_to_address_paths(key_chain, dest);
    inp_req.set_nonce(outpoint.nonce().value());
    match outpoint.account() {
        AccountSpending::DelegationBalance(delegation_id, amount) => {
            let mut deleg_balance_req = MintlayerAccountSpendingDelegationBalance::new();
            deleg_balance_req
                .set_delegation_id(Address::new(chain_config, *delegation_id)?.into_string());
            deleg_balance_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            inp_req.delegation_balance = Some(deleg_balance_req).into();
        }
    }
    let mut inp = MintlayerTxInput::new();
    inp.account = Some(inp_req).into();
    Ok(inp)
}

fn to_trezor_utxo_input(
    outpoint: &common::chain::UtxoOutPoint,
    dest: &Destination,
    key_chain: &impl AccountKeyChains,
) -> SignerResult<MintlayerTxInput> {
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

    inp_req.addresses = destination_to_address_paths(key_chain, dest);

    let mut inp = MintlayerTxInput::new();
    inp.utxo = Some(inp_req).into();
    Ok(inp)
}

/// Find the derivation paths to the key in the destination, or multiple in the case of a multisig
fn destination_to_address_paths(
    key_chain: &impl AccountKeyChains,
    dest: &Destination,
) -> Vec<MintlayerAddressPath> {
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            vec![MintlayerAddressPath {
                address_n,
                ..Default::default()
            }]
        }
        Some(FoundPubKey::Standalone(_)) => {
            unimplemented!("standalone keys with trezor")
        }
        None => {
            if let Some(challenge) = key_chain.find_multisig_challenge(dest) {
                challenge
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
                    .collect()
            } else {
                vec![]
            }
        }
    }
}

fn to_trezor_output_value(
    output_value: &OutputValue,
    additional_info: &TxAdditionalInfo,
    chain_config: &ChainConfig,
) -> SignerResult<MintlayerOutputValue> {
    to_trezor_output_value_with_token_info(
        output_value,
        |token_id| additional_info.get_token_info(&token_id),
        chain_config,
    )
}

fn to_trezor_utxo_msgs(
    ptx: &PartiallySignedTransaction,
    chain_config: &ChainConfig,
) -> SignerResult<BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTxOutput>>> {
    let mut utxos: BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTxOutput>> = BTreeMap::new();

    for (utxo, inp) in ptx.input_utxos().iter().zip(ptx.tx().inputs()) {
        match inp {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo.as_ref().ok_or(SignerError::MissingUtxo)?;
                let id = match outpoint.source_id() {
                    OutPointSourceId::Transaction(id) => id.to_hash().0,
                    OutPointSourceId::BlockReward(id) => id.to_hash().0,
                };
                let out = to_trezor_output_msg(chain_config, utxo, ptx.additional_infos())?;
                utxos.entry(id).or_default().insert(outpoint.output_index(), out);
            }
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => {}
        }
    }

    Ok(utxos)
}

fn to_trezor_output_msg(
    chain_config: &ChainConfig,
    out: &TxOutput,
    additional_info: &TxAdditionalInfo,
) -> SignerResult<MintlayerTxOutput> {
    let res = match out {
        TxOutput::Transfer(value, dest) => {
            let mut out_req = MintlayerTransferTxOutput::new();
            out_req.value = Some(to_trezor_output_value(
                value,
                additional_info,
                chain_config,
            )?)
            .into();
            out_req.set_address(Address::new(chain_config, dest.clone())?.into_string());

            let mut out = MintlayerTxOutput::new();
            out.transfer = Some(out_req).into();
            out
        }
        TxOutput::LockThenTransfer(value, dest, lock) => {
            let mut out_req = MintlayerLockThenTransferTxOutput::new();
            out_req.value = Some(to_trezor_output_value(
                value,
                additional_info,
                chain_config,
            )?)
            .into();
            out_req.set_address(Address::new(chain_config, dest.clone())?.into_string());

            out_req.lock = Some(to_trezor_output_lock(lock)).into();

            let mut out = MintlayerTxOutput::new();
            out.lock_then_transfer = Some(out_req).into();
            out
        }
        TxOutput::Burn(value) => {
            let mut out_req = MintlayerBurnTxOutput::new();
            out_req.value = Some(to_trezor_output_value(
                value,
                additional_info,
                chain_config,
            )?)
            .into();

            let mut out = MintlayerTxOutput::new();
            out.burn = Some(out_req).into();
            out
        }
        TxOutput::CreateDelegationId(dest, pool_id) => {
            let mut out_req = MintlayerCreateDelegationIdTxOutput::new();
            out_req.set_pool_id(Address::new(chain_config, *pool_id)?.into_string());
            out_req.set_destination(Address::new(chain_config, dest.clone())?.into_string());
            let mut out = MintlayerTxOutput::new();
            out.create_delegation_id = Some(out_req).into();
            out
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            let mut out_req = MintlayerDelegateStakingTxOutput::new();
            out_req.set_delegation_id(Address::new(chain_config, *delegation_id)?.into_string());
            out_req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            let mut out = MintlayerTxOutput::new();
            out.delegate_staking = Some(out_req).into();
            out
        }
        TxOutput::CreateStakePool(pool_id, pool_data) => {
            let mut out_req = MintlayerCreateStakePoolTxOutput::new();
            out_req.set_pool_id(Address::new(chain_config, *pool_id)?.into_string());

            out_req.set_pledge(pool_data.pledge().into_atoms().to_be_bytes().to_vec());
            out_req
                .set_staker(Address::new(chain_config, pool_data.staker().clone())?.into_string());
            out_req.set_decommission_key(
                Address::new(chain_config, pool_data.decommission_key().clone())?.into_string(),
            );
            out_req.set_vrf_public_key(
                Address::new(chain_config, pool_data.vrf_public_key().clone())?.into_string(),
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
            out_req.set_pool_id(Address::new(chain_config, *pool_id)?.into_string());
            out_req.set_destination(Address::new(chain_config, dest.clone())?.into_string());
            let staker_balance = additional_info
                .get_pool_info(pool_id)
                .ok_or(SignerError::MissingTxExtraInfo)?
                .staker_balance;
            out_req.set_staker_balance(staker_balance.into_atoms().to_be_bytes().to_vec());
            let mut out = MintlayerTxOutput::new();
            out.produce_block_from_stake = Some(out_req).into();
            out
        }
        TxOutput::IssueFungibleToken(token_data) => {
            let mut out_req = MintlayerIssueFungibleTokenTxOutput::new();

            match token_data.as_ref() {
                TokenIssuance::V1(data) => {
                    out_req.set_authority(
                        Address::new(chain_config, data.authority.clone())?.into_string(),
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
            out_req.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            out_req.set_destination(Address::new(chain_config, dest.clone())?.into_string());
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
                            )?
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
        TxOutput::Htlc(value, lock) => {
            let mut out_req = MintlayerHtlcTxOutput::new();
            out_req.value = Some(to_trezor_output_value(
                value,
                additional_info,
                chain_config,
            )?)
            .into();
            out_req.secret_hash = Some(lock.secret_hash.as_bytes().to_vec());

            out_req
                .set_spend_key(Address::new(chain_config, lock.spend_key.clone())?.into_string());
            out_req
                .set_refund_key(Address::new(chain_config, lock.refund_key.clone())?.into_string());

            out_req.refund_timelock = Some(to_trezor_output_lock(&lock.refund_timelock)).into();

            let mut out = MintlayerTxOutput::new();
            out.htlc = Some(out_req).into();
            out
        }
        TxOutput::CreateOrder(data) => {
            let mut out_req = MintlayerCreateOrderTxOutput::new();

            out_req.set_conclude_key(
                Address::new(chain_config, data.conclude_key().clone())?.into_string(),
            );

            out_req.ask = Some(to_trezor_output_value(
                data.ask(),
                additional_info,
                chain_config,
            )?)
            .into();
            out_req.give = Some(to_trezor_output_value(
                data.give(),
                additional_info,
                chain_config,
            )?)
            .into();

            let mut out = MintlayerTxOutput::new();
            out.create_order = Some(out_req).into();
            out
        }
    };
    Ok(res)
}

fn to_trezor_output_value_with_token_info<'a, F>(
    value: &OutputValue,
    additional_info: F,
    chain_config: &ChainConfig,
) -> Result<MintlayerOutputValue, SignerError>
where
    F: Fn(TokenId) -> Option<&'a TokenAdditionalInfo>,
{
    match value {
        OutputValue::Coin(amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            Ok(value)
        }
        OutputValue::TokenV1(token_id, amount) => {
            let mut value = MintlayerOutputValue::new();
            value.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            let info = additional_info(*token_id).ok_or(SignerError::MissingTxExtraInfo)?;

            let mut token_value = MintlayerTokenOutputValue::new();
            token_value.set_token_id(Address::new(chain_config, *token_id)?.into_string());
            token_value.set_number_of_decimals(info.num_decimals as u32);
            token_value.set_token_ticker(info.ticker.clone());
            value.token = Some(token_value).into();
            Ok(value)
        }
        OutputValue::TokenV0(_) => Err(SignerError::UnsupportedTokensV0),
    }
}

fn to_trezor_output_lock(lock: &OutputTimeLock) -> trezor_client::protos::MintlayerOutputTimeLock {
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
    lock_req
}

#[derive(Clone)]
pub struct TrezorSignerProvider {
    client: Arc<Mutex<Trezor>>,
    data: TrezorData,
}

impl std::fmt::Debug for TrezorSignerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrezorSignerProvider")
    }
}

impl TrezorSignerProvider {
    pub fn new() -> Result<Self, TrezorError> {
        let (client, data) =
            find_trezor_device().map_err(|err| TrezorError::DeviceError(err.to_string()))?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            data,
        })
    }

    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
    ) -> WalletResult<Self> {
        let (client, data) = find_trezor_device().map_err(SignerError::TrezorError)?;

        let provider = Self {
            client: Arc::new(Mutex::new(client)),
            data,
        };

        check_public_keys(db_tx, &provider, chain_config)?;

        Ok(provider)
    }

    fn fetch_extended_pub_key(
        &self,
        chain_config: &Arc<ChainConfig>,
        account_index: U31,
    ) -> SignerResult<ExtendedPublicKey> {
        let derivation_path = make_account_path(chain_config, account_index);
        let account_path =
            derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect();
        let chain_type = to_trezor_chain_type(chain_config);
        let xpub = self
            .client
            .lock()
            .expect("poisoned lock")
            .mintlayer_get_public_key(chain_type, account_path)
            .map_err(|e| SignerError::TrezorError(TrezorError::DeviceError(e.to_string())))?;
        let chain_code = ChainCode::from(xpub.chain_code.0);
        let account_pubkey = Secp256k1ExtendedPublicKey::new(
            derivation_path,
            chain_code,
            Secp256k1PublicKey::from_bytes(&xpub.public_key.serialize())
                .map_err(|_| SignerError::TrezorError(TrezorError::InvalidKey))?,
        );
        let account_pubkey = ExtendedPublicKey::new(account_pubkey);
        Ok(account_pubkey)
    }
}

fn to_trezor_chain_type(chain_config: &ChainConfig) -> MintlayerChainType {
    match chain_config.chain_type() {
        ChainType::Mainnet => MintlayerChainType::Mainnet,
        ChainType::Testnet => MintlayerChainType::Testnet,
        ChainType::Regtest => MintlayerChainType::Regtest,
        ChainType::Signet => MintlayerChainType::Signet,
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

    if loaded_acc.key_chain().account_public_key() == &expected_pk {
        return Ok(());
    }

    if let Some(data) = db_tx.get_hardware_wallet_data()? {
        match data {
            HardwareWalletData::Trezor(data) => {
                // If the device_id and label are the same but public keys are different, maybe a
                // different passphrase was used
                if data == provider.data {
                    return Err(WalletError::HardwareWalletDifferentPassphrase);
                } else {
                    return Err(WalletError::HardwareWalletDifferentDevice(
                        data.device_id,
                        provider.data.device_id.clone(),
                        data.label,
                        provider.data.label.clone(),
                    ));
                }
            }
        }
    }

    Err(WalletError::HardwareWalletDifferentFile)
}

fn find_trezor_device() -> Result<(Trezor, TrezorData), TrezorError> {
    let mut devices = find_devices(false)
        .into_iter()
        .filter(|device| device.model == Model::Trezor || device.model == Model::TrezorEmulator)
        .collect_vec();

    let device = match devices.len() {
        0 => return Err(TrezorError::NoDeviceFound),
        1 => devices.remove(0),
        _ => return Err(TrezorError::NoUniqueDeviceFound),
    };
    let mut client = device.connect().map_err(|e| TrezorError::DeviceError(e.to_string()))?;
    client.init_device(None).map_err(|e| TrezorError::DeviceError(e.to_string()))?;

    let features = client.features().ok_or(TrezorError::CannotGetDeviceFeatures)?;
    ensure!(
        features
            .capabilities
            .iter()
            .filter_map(|c| c.enum_value().ok())
            .contains(&Capability::Capability_Mintlayer),
        TrezorError::MintlayerFeaturesNotSupported
    );

    let data = TrezorData {
        label: features.label().to_owned(),
        device_id: features.device_id().to_owned(),
    };

    Ok((client, data))
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

    fn get_hardware_wallet_data(&mut self) -> Option<HardwareWalletData> {
        Some(HardwareWalletData::Trezor(self.data.clone()))
    }
}

#[cfg(feature = "trezor-emulator")]
#[cfg(test)]
mod tests;
