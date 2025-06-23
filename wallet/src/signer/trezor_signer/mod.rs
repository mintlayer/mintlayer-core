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
        output_value::OutputValue,
        signature::{
            inputsig::{
                arbitrary_message::ArbitraryMessageSignature,
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                authorize_pubkey_spend::AuthorizedPublicKeySpend,
                authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
                classical_multisig::{
                    authorize_classical_multisig::{
                        sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                        ClassicalMultisigCompletionStatus,
                    },
                    multisig_partial_signature::{self, PartiallySignedMultisigChallenge},
                },
                htlc::produce_uniparty_signature_for_htlc_input,
                standard_signature::StandardInputSignature,
                InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
            DestinationSigError,
        },
        timelock::OutputTimeLock,
        tokens::{NftIssuance, TokenId, TokenIssuance, TokenTotalSupply},
        AccountCommand, AccountSpending, ChainConfig, Destination, OrderAccountCommand,
        OutPointSourceId, SignedTransactionIntent, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Idable, H256},
};
use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{chain_code::ChainCode, derivable::Derivable, u31::U31},
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
    signature::SignatureKind,
    PrivateKey, SigAuxDataProvider, Signature, SignatureError,
};
use itertools::Itertools;
use randomness::make_true_rng;
use serialization::Encode;
use trezor_client::{
    client::{mintlayer::MintlayerSignature, TransactionId},
    find_devices,
    protos::{
        features::Capability,
        mintlayer_tx_ack::{MintlayerTxInput, MintlayerTxOutput},
        MintlayerAccountCommandTxInput, MintlayerAccountSpendingDelegationBalance,
        MintlayerAccountTxInput, MintlayerAddressPath, MintlayerAddressType, MintlayerBurnTxOutput,
        MintlayerChainType, MintlayerChangeTokenAuthority, MintlayerChangeTokenMetadataUri,
        MintlayerConcludeOrder, MintlayerConcludeOrderV1, MintlayerCreateDelegationIdTxOutput,
        MintlayerCreateOrderTxOutput, MintlayerCreateStakePoolTxOutput,
        MintlayerDataDepositTxOutput, MintlayerDelegateStakingTxOutput, MintlayerFillOrder,
        MintlayerFillOrderV1, MintlayerFreezeOrder, MintlayerFreezeToken, MintlayerHtlcTxOutput,
        MintlayerIssueFungibleTokenTxOutput, MintlayerIssueNftTxOutput,
        MintlayerLockThenTransferTxOutput, MintlayerLockTokenSupply, MintlayerMintTokens,
        MintlayerOrderCommandTxInput, MintlayerOutputValue, MintlayerProduceBlockFromStakeTxOutput,
        MintlayerTokenOutputValue, MintlayerTokenTotalSupply, MintlayerTokenTotalSupplyType,
        MintlayerUnfreezeToken, MintlayerUnmintTokens, MintlayerUtxoType,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FoundDevice {
    pub name: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SelectedDevice {
    pub device_id: String,
}

/// Signer errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum TrezorError {
    #[error("No connected Trezor device found")]
    NoDeviceFound,
    #[error("No compatible Trezor device found with Mintlayer capabilities")]
    NoCompatibleDeviceFound,
    #[error("There are multiple connected Trezor devices found {0:?}")]
    NoUniqueDeviceFound(Vec<FoundDevice>),
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
    #[error("Missing multisig index for signature returned from Device")]
    MissingMultisigIndexForSignature,
    #[error("Multiple signatures returned for a single address from Device")]
    MultipleSignaturesReturned,
    #[error("A multisig signature was returned for a single address from Device")]
    MultisigSignatureReturned,
    #[error("The file being loaded is a software wallet and does not correspond to the connected hardware wallet")]
    HardwareWalletDifferentFile,
    #[error("Public keys mismatch. Wrong device or passphrase:\nfile device id \"{file_device_id}\", connected device id \"{connected_device_id}\",\nfile label \"{file_label}\" and connected device label \"{connected_device_id}\"")]
    HardwareWalletDifferentMnemonicOrPassphrase {
        file_device_id: String,
        connected_device_id: String,
        file_label: String,
        connected_device_label: String,
    },
    #[error("The file being loaded corresponds to the connected hardware wallet, but public keys are different. Maybe a wrong passphrase was entered?")]
    HardwareWalletDifferentPassphrase,
    #[error("Missing hardware wallet data in database")]
    MissingHardwareWalletData,
}

// Note:
// 1) sig_aux_data_provider is only used for signing with standalone keys.
// 2) signing with Trezor is equivalent to signing with the software signer using PredefinedSigAuxDataProvider.
pub struct TrezorSigner {
    chain_config: Arc<ChainConfig>,
    client: Arc<Mutex<Trezor>>,
    session_id: Vec<u8>,
    sig_aux_data_provider: Mutex<Box<dyn SigAuxDataProvider>>,
}

impl TrezorSigner {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        client: Arc<Mutex<Trezor>>,
        session_id: Vec<u8>,
    ) -> Self {
        Self::new_with_sig_aux_data_provider(
            chain_config,
            client,
            session_id,
            Box::new(make_true_rng()),
        )
    }

    pub fn new_with_sig_aux_data_provider(
        chain_config: Arc<ChainConfig>,
        client: Arc<Mutex<Trezor>>,
        session_id: Vec<u8>,
        sig_aux_data_provider: Box<dyn SigAuxDataProvider>,
    ) -> Self {
        Self {
            chain_config,
            client,
            session_id,
            sig_aux_data_provider: Mutex::new(sig_aux_data_provider),
        }
    }

    /// Calls initialize on the device with the current session_id.
    ///
    /// If the operation fails due to an USB error (which may indicate a lost connection to the device),
    /// the function will attempt to reconnect to the Trezor device once before returning an error.
    fn check_session(
        &mut self,
        db_tx: &impl WalletStorageReadLocked,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<()> {
        let mut client = self.client.lock().expect("poisoned lock");

        match client.init_device(Some(self.session_id.clone())) {
            Ok(_) => Ok(()),
            // In case of a USB error try to reconnect, and try again
            Err(trezor_client::Error::TransportSendMessage(
                trezor_client::transport::error::Error::Usb(_),
            )) => {
                let (mut new_client, data, session_id) = find_trezor_device_from_db(db_tx, None)?;

                check_public_keys_against_key_chain(
                    db_tx,
                    &mut new_client,
                    &data,
                    key_chain,
                    &self.chain_config,
                )?;

                *client = new_client;
                self.session_id = session_id;
                Ok(())
            }
            Err(err) => Err(SignerError::TrezorError(TrezorError::DeviceError(
                err.to_string(),
            ))),
        }
    }

    /// Attempts to perform an operation on the Trezor client.
    ///
    /// If the operation fails due to an USB error (which may indicate a lost connection to the device),
    /// the function will attempt to reconnect to the Trezor device once before returning an error.
    fn perform_trezor_operation<F, R>(
        &mut self,
        operation: F,
        db_tx: &impl WalletStorageReadLocked,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<R>
    where
        F: Fn(&mut Trezor) -> Result<R, trezor_client::Error>,
    {
        self.check_session(db_tx, key_chain)?;

        let mut client = self.client.lock().expect("poisoned lock");
        operation(&mut client).map_err(|e| TrezorError::DeviceError(e.to_string()).into())
    }

    #[allow(clippy::too_many_arguments)]
    fn make_signature<'a, 'b, F, F2>(
        &self,
        signatures: &[MintlayerSignature],
        standalone_inputs: &'a [StandaloneInput],
        destination: &'b Destination,
        sighash_type: SigHashType,
        sighash: H256,
        key_chain: &impl AccountKeyChains,
        make_witness: F,
        sign_with_standalone_private_key: F2,
    ) -> SignerResult<(Option<InputWitness>, SignatureStatus)>
    where
        F: Fn(StandardInputSignature) -> InputWitness,
        F2: Fn(&'a StandaloneInput, &'b Destination) -> SignerResult<InputWitness>,
    {
        match destination {
            Destination::AnyoneCanSpend => Ok((
                Some(InputWitness::NoSignature(None)),
                SignatureStatus::FullySigned,
            )),
            Destination::PublicKeyHash(_) => {
                if let Some(signature) = single_signature(signatures)? {
                    let pk = key_chain
                        .find_public_key(destination)
                        .ok_or(SignerError::DestinationNotFromThisWallet)?
                        .into_public_key();
                    let sig = Signature::from_raw_data(
                        &signature.signature,
                        SignatureKind::Secp256k1Schnorr,
                    )
                    .map_err(TrezorError::SignatureError)?;
                    let sig = AuthorizedPublicKeyHashSpend::new(pk, sig);
                    let sig = make_witness(StandardInputSignature::new(sighash_type, sig.encode()));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    let standalone = match standalone_inputs {
                        [] => return Ok((None, SignatureStatus::NotSigned)),
                        [standalone] => standalone,
                        _ => return Err(TrezorError::MultisigSignatureReturned.into()),
                    };

                    let sig = sign_with_standalone_private_key(standalone, destination)?;
                    Ok((Some(sig), SignatureStatus::FullySigned))
                }
            }
            Destination::PublicKey(_) => {
                if let Some(signature) = single_signature(signatures)? {
                    let sig = Signature::from_raw_data(
                        &signature.signature,
                        SignatureKind::Secp256k1Schnorr,
                    )
                    .map_err(TrezorError::SignatureError)?;
                    let sig = AuthorizedPublicKeySpend::new(sig);
                    let sig = make_witness(StandardInputSignature::new(sighash_type, sig.encode()));

                    Ok((Some(sig), SignatureStatus::FullySigned))
                } else {
                    let standalone = match standalone_inputs {
                        [] => return Ok((None, SignatureStatus::NotSigned)),
                        [standalone] => standalone,
                        _ => return Err(TrezorError::MultisigSignatureReturned.into()),
                    };

                    let sig = sign_with_standalone_private_key(standalone, destination)?;
                    Ok((Some(sig), SignatureStatus::FullySigned))
                }
            }
            Destination::ClassicMultisig(_) => {
                if let Some(challenge) = key_chain.find_multisig_challenge(destination) {
                    let (current_signatures, status) = self.update_and_check_multisig(
                        signatures,
                        AuthorizedClassicalMultisigSpend::new_empty(challenge.clone()),
                        sighash,
                    )?;

                    let (current_signatures, status) = self.sign_with_standalone_private_keys(
                        current_signatures,
                        standalone_inputs,
                        status,
                        sighash,
                    )?;

                    let sig = make_witness(StandardInputSignature::new(
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
            .map(|out| to_trezor_output_msg(&self.chain_config, out, ptx.additional_info()))
            .collect();
        outputs
    }

    fn check_signature_status(
        &self,
        sighash: H256,
        current_signatures: &AuthorizedClassicalMultisigSpend,
    ) -> Result<SignatureStatus, SignerError> {
        let msg = sighash.encode();
        let verifier = PartiallySignedMultisigChallenge::from_partial(
            &self.chain_config,
            &msg,
            current_signatures,
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
                SignatureStatus::InvalidSignature
            }
        };
        Ok(status)
    }

    fn update_and_check_multisig(
        &self,
        signatures: &[MintlayerSignature],
        mut current_signatures: AuthorizedClassicalMultisigSpend,
        sighash: H256,
    ) -> SignerResult<(AuthorizedClassicalMultisigSpend, SignatureStatus)> {
        for sig in signatures {
            let idx = sig.multisig_idx.ok_or(TrezorError::MissingMultisigIndexForSignature)?;
            let sig = Signature::from_raw_data(&sig.signature, SignatureKind::Secp256k1Schnorr)
                .map_err(TrezorError::SignatureError)?;
            current_signatures.add_signature(idx as u8, sig);
        }

        let status = self.check_signature_status(sighash, &current_signatures)?;

        Ok((current_signatures, status))
    }

    fn sign_with_standalone_private_keys(
        &self,
        current_signatures: AuthorizedClassicalMultisigSpend,
        standalone_inputs: &[StandaloneInput],
        new_status: SignatureStatus,
        sighash: H256,
    ) -> SignerResult<(AuthorizedClassicalMultisigSpend, SignatureStatus)> {
        let challenge = current_signatures.challenge().clone();

        standalone_inputs.iter().try_fold(
            (current_signatures, new_status),
            |(mut current_signatures, mut status), inp| -> SignerResult<_> {
                if status == SignatureStatus::FullySigned {
                    return Ok((current_signatures, status));
                }

                let key_index =
                    inp.multisig_idx.ok_or(TrezorError::MissingMultisigIndexForSignature)?;
                let res = sign_classical_multisig_spending(
                    &self.chain_config,
                    key_index as u8,
                    &inp.private_key,
                    &challenge,
                    &sighash,
                    current_signatures,
                    self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut(),
                )
                .map_err(DestinationSigError::ClassicalMultisigSigningFailed)?;

                match res {
                    ClassicalMultisigCompletionStatus::Complete(signatures) => {
                        current_signatures = signatures;
                        status = SignatureStatus::FullySigned;
                    }
                    ClassicalMultisigCompletionStatus::Incomplete(signatures) => {
                        current_signatures = signatures;
                        status = SignatureStatus::PartialMultisig {
                            required_signatures: challenge.min_required_signatures(),
                            num_signatures: current_signatures.signatures().len() as u8,
                        };
                    }
                };

                Ok((current_signatures, status))
            },
        )
    }
}

fn find_trezor_device_from_db(
    db_tx: &impl WalletStorageReadLocked,
    selected_device_id: Option<String>,
) -> SignerResult<(Trezor, TrezorData, Vec<u8>)> {
    if let Some(device_id) = selected_device_id {
        return find_trezor_device(Some(SelectedDevice { device_id }))
            .map_err(SignerError::TrezorError);
    }

    if let Some(HardwareWalletData::Trezor(data)) = db_tx.get_hardware_wallet_data()? {
        let selected = SelectedDevice {
            device_id: data.device_id,
        };

        find_trezor_device(Some(selected)).map_err(SignerError::TrezorError)
    } else {
        Err(SignerError::TrezorError(
            TrezorError::MissingHardwareWalletData,
        ))
    }
}

impl Signer for TrezorSigner {
    fn sign_tx(
        &mut self,
        ptx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )> {
        let (inputs, standalone_inputs) =
            to_trezor_input_msgs(&ptx, key_chain, &self.chain_config, db_tx)?;
        let outputs = self.to_trezor_output_msgs(&ptx)?;
        let utxos = to_trezor_utxo_msgs(&ptx, &self.chain_config)?;
        let chain_type = to_trezor_chain_type(&self.chain_config);

        let new_signatures = self.perform_trezor_operation(
            move |client| {
                client.mintlayer_sign_tx(chain_type, inputs.clone(), outputs.clone(), utxos.clone())
            },
            db_tx,
            key_chain,
        )?;

        let inputs_utxo_refs: Vec<_> = ptx.input_utxos().iter().map(|u| u.as_ref()).collect();

        let (witnesses, prev_statuses, new_statuses) = itertools::process_results(ptx
            .witnesses()
            .iter()
            .enumerate()
            .zip(ptx.input_utxos())
            .zip(ptx.destinations())
            .zip(ptx.htlc_secrets())
            .map(|((((input_index, witness), input_utxo), destination), secret)| -> SignerResult<_> {
                let is_htlc_input = input_utxo.as_ref().is_some_and(is_htlc_utxo);
                let make_witness = |sig: StandardInputSignature| {
                    let sig = if is_htlc_input {
                        let sighash_type = sig.sighash_type();
                        let spend = if let Some(htlc_secret) = secret {
                            AuthorizedHashedTimelockContractSpend::Secret(
                                htlc_secret.clone(),
                                sig.into_raw_signature(),
                            )
                        } else {
                            AuthorizedHashedTimelockContractSpend::Multisig(sig.into_raw_signature())
                        };

                        let serialized_spend = spend.encode();
                        StandardInputSignature::new(sighash_type, serialized_spend)
                    }
                    else {
                        sig
                    };

                    InputWitness::Standard(sig)
                };

                let sign_with_standalone_private_key = |standalone, destination| {
                    sign_input_with_standalone_key(
                        secret,
                        standalone,
                        destination,
                        &ptx,
                        &inputs_utxo_refs,
                        input_index,
                        self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut()
                    )
                };

                match witness {
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
                                    input_index,
                                )
                                .is_ok()
                                {
                                    Ok((
                                        Some(w.clone()),
                                        SignatureStatus::FullySigned,
                                        SignatureStatus::FullySigned,
                                    ))
                                } else if let Destination::ClassicMultisig(_) = destination {
                                    let sighash = signature_hash(
                                        sig.sighash_type(),
                                        ptx.tx(),
                                        &inputs_utxo_refs,
                                        input_index,
                                    )?;

                                    let current_signatures = if is_htlc_input {
                                        let htlc_spend = AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())?;
                                        match htlc_spend {
                                            AuthorizedHashedTimelockContractSpend::Secret(_, _) => {
                                                return Err(SignerError::HtlcMultisigDestinationExpected);
                                            },
                                            AuthorizedHashedTimelockContractSpend::Multisig(raw_sig) => {
                                                AuthorizedClassicalMultisigSpend::from_data(&raw_sig)?
                                            },
                                        }
                                    } else {
                                        AuthorizedClassicalMultisigSpend::from_data(sig.raw_signature())?
                                    };

                                    let previous_status = SignatureStatus::PartialMultisig {
                                        required_signatures: current_signatures
                                            .challenge()
                                            .min_required_signatures(),
                                        num_signatures: current_signatures.signatures().len() as u8,
                                    };

                                    let (current_signatures, new_status) = if let Some(signatures) = new_signatures.get(input_index)
                                    {
                                        self.update_and_check_multisig(signatures, current_signatures, sighash)?
                                    } else {
                                        (current_signatures, previous_status)
                                    };

                                    let (current_signatures, new_status) =
                                        self.sign_with_standalone_private_keys(
                                            current_signatures,
                                            standalone_inputs.get(&(input_index as u32)).map_or(&[], |x| x.as_slice()),
                                            new_status,
                                            sighash
                                        )?;

                                    let sighash_type = SigHashType::all();
                                    let sig = make_witness(StandardInputSignature::new(
                                        sighash_type,
                                        current_signatures.encode(),
                                    ));

                                    Ok((Some(sig), previous_status, new_status))
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
                    None => match (destination, new_signatures.get(input_index)) {
                        (Some(destination), Some(sig)) => {
                            let sighash_type = SigHashType::all();
                            let sighash = signature_hash(sighash_type, ptx.tx(), &inputs_utxo_refs, input_index)?;
                            let (sig, status) = self.make_signature(
                                sig,
                                standalone_inputs.get(&(input_index as u32)).map_or(&[], |x| x.as_slice()),
                                destination,
                                sighash_type,
                                sighash,
                                key_chain,
                                make_witness,
                                sign_with_standalone_private_key,
                            )?;
                            Ok((sig, SignatureStatus::NotSigned, status))
                        }
                        (Some(destination), None) => {
                            let standalone = match standalone_inputs.get(&(input_index as u32)).map(|x| x.as_slice()) {
                                Some([standalone]) => standalone,
                                Some(_) => return Err(TrezorError::MultisigSignatureReturned.into()),
                                None => return Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned))
                            };

                            let sig = sign_input_with_standalone_key(
                                secret,
                                standalone,
                                destination,
                                &ptx,
                                &inputs_utxo_refs,
                                input_index,
                                self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut()
                            )?;

                            Ok((Some(sig), SignatureStatus::NotSigned, SignatureStatus::FullySigned))
                        }
                        (None, _) => {
                            Ok((None, SignatureStatus::NotSigned, SignatureStatus::NotSigned))
                        }
                    },
                }
            }),
            |iter| iter.multiunzip()
        )?;

        Ok((ptx.with_witnesses(witnesses), prev_statuses, new_statuses))
    }

    fn sign_challenge(
        &mut self,
        message: &[u8],
        destination: &Destination,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<ArbitraryMessageSignature> {
        let data = match key_chain.find_public_key(destination) {
            Some(FoundPubKey::Hierarchy(xpub)) => {
                let address_n: Vec<_> = xpub
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

                let sig = self.perform_trezor_operation(
                    move |client| {
                        client.mintlayer_sign_message(
                            chain_type,
                            address_n.clone(),
                            addr_type,
                            message.to_vec(),
                        )
                    },
                    db_tx,
                    key_chain,
                )?;

                let signature = Signature::from_raw_data(&sig, SignatureKind::Secp256k1Schnorr)
                    .map_err(TrezorError::SignatureError)?;

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
            Some(FoundPubKey::Standalone(acc_public_key)) => {
                let standalone_pk = db_tx
                    .get_account_standalone_private_key(&acc_public_key)?
                    .ok_or(SignerError::DestinationNotFromThisWallet)?;

                let sig = ArbitraryMessageSignature::produce_uniparty_signature(
                    &standalone_pk,
                    destination,
                    message,
                    self.sig_aux_data_provider.lock().expect("poisoned mutex").as_mut(),
                )?;
                return Ok(sig);
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
            let dest = SignedTransactionIntent::normalize_destination(dest);
            let sig = self.sign_challenge(message_to_sign.as_bytes(), &dest, key_chain, db_tx)?;
            signatures.push(sig.into_raw());
        }

        Ok(SignedTransactionIntent::from_components(
            message_to_sign,
            signatures,
            input_destinations,
            &self.chain_config,
        )?)
    }
}

fn sign_input_with_standalone_key<AuxP: SigAuxDataProvider + ?Sized>(
    secret: &Option<common::chain::htlc::HtlcSecret>,
    standalone: &StandaloneInput,
    destination: &Destination,
    ptx: &PartiallySignedTransaction,
    inputs_utxo_refs: &[Option<&TxOutput>],
    input_index: usize,
    sig_aux_data_provider: &mut AuxP,
) -> SignerResult<InputWitness> {
    let sighash_type = SigHashType::all();
    match secret {
        Some(htlc_secret) => produce_uniparty_signature_for_htlc_input(
            &standalone.private_key,
            sighash_type,
            destination.clone(),
            ptx.tx(),
            inputs_utxo_refs,
            input_index,
            htlc_secret.clone(),
            sig_aux_data_provider,
        ),
        None => StandardInputSignature::produce_uniparty_signature_for_input(
            &standalone.private_key,
            sighash_type,
            destination.clone(),
            ptx.tx(),
            inputs_utxo_refs,
            input_index,
            sig_aux_data_provider,
        ),
    }
    .map(InputWitness::Standard)
    .map_err(SignerError::SigningError)
}

fn to_trezor_input_msgs(
    ptx: &PartiallySignedTransaction,
    key_chain: &impl AccountKeyChains,
    chain_config: &ChainConfig,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<MintlayerTxInput>, StandaloneInputs)> {
    let res: (Vec<_>, BTreeMap<_, _>) = itertools::process_results(
        ptx.tx().inputs().iter().zip(ptx.destinations()).enumerate().map(
            |(idx, (inp, dest))| -> SignerResult<_> {
                let (address_paths, standalone_inputs) =
                    dest.as_ref().map_or(Ok((vec![], vec![])), |dest| {
                        destination_to_address_paths(key_chain, dest, db_tx)
                    })?;

                let input = match inp {
                    TxInput::Utxo(outpoint) => to_trezor_utxo_input(outpoint, address_paths),
                    TxInput::Account(outpoint) => {
                        to_trezor_account_input(chain_config, address_paths, outpoint)
                    }
                    TxInput::AccountCommand(nonce, command) => to_trezor_account_command_input(
                        chain_config,
                        address_paths,
                        nonce,
                        command,
                        ptx.additional_info(),
                    ),
                    TxInput::OrderAccountCommand(command) => to_trezor_order_command_input(
                        chain_config,
                        address_paths,
                        command,
                        ptx.additional_info(),
                    ),
                }?;

                Ok((input, (idx as u32, standalone_inputs)))
            },
        ),
        |iter| iter.unzip(),
    )?;

    Ok(res)
}

fn to_trezor_account_command_input(
    chain_config: &ChainConfig,
    address_paths: Vec<MintlayerAddressPath>,
    nonce: &common::chain::AccountNonce,
    command: &AccountCommand,
    additional_info: &TxAdditionalInfo,
) -> SignerResult<MintlayerTxInput> {
    let mut inp_req = MintlayerAccountCommandTxInput::new();
    inp_req.addresses = address_paths;
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
            req.set_is_token_unfreezable(unfreezable.as_bool());

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

fn to_trezor_order_command_input(
    chain_config: &ChainConfig,
    address_paths: Vec<MintlayerAddressPath>,
    command: &OrderAccountCommand,
    additional_info: &TxAdditionalInfo,
) -> SignerResult<MintlayerTxInput> {
    let mut inp_req = MintlayerOrderCommandTxInput::new();
    inp_req.addresses = address_paths;
    match command {
        OrderAccountCommand::FreezeOrder(order_id) => {
            let mut req = MintlayerFreezeOrder::new();
            req.set_order_id(Address::new(chain_config, *order_id)?.into_string());

            inp_req.freeze = Some(req).into();
        }
        OrderAccountCommand::ConcludeOrder(order_id) => {
            let mut req = MintlayerConcludeOrderV1::new();
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

            inp_req.conclude = Some(req).into();
        }
        OrderAccountCommand::FillOrder(order_id, amount, dest) => {
            let mut req = MintlayerFillOrderV1::new();
            req.set_order_id(Address::new(chain_config, *order_id)?.into_string());
            req.set_amount(amount.into_atoms().to_be_bytes().to_vec());
            req.set_destination(Address::new(chain_config, dest.clone())?.into_string());

            let OrderAdditionalInfo {
                initially_asked,
                initially_given,
                ask_balance: _,
                give_balance: _,
            } = additional_info
                .get_order_info(order_id)
                .ok_or(SignerError::MissingTxExtraInfo)?;

            req.initially_asked = Some(to_trezor_output_value(
                initially_asked,
                additional_info,
                chain_config,
            )?)
            .into();

            req.initially_given = Some(to_trezor_output_value(
                initially_given,
                additional_info,
                chain_config,
            )?)
            .into();

            inp_req.fill = Some(req).into();
        }
    }
    let mut inp = MintlayerTxInput::new();
    inp.order_command = Some(inp_req).into();
    Ok(inp)
}

/// Construct a new OutputValue with a new amount
fn value_with_new_amount(
    initial_value: &OutputValue,
    new_amount: &Amount,
) -> Result<OutputValue, SignerError> {
    match initial_value {
        OutputValue::Coin(_) => Ok(OutputValue::Coin(*new_amount)),
        OutputValue::TokenV1(id, _) => Ok(OutputValue::TokenV1(*id, *new_amount)),
        OutputValue::TokenV0(_) => Err(SignerError::UnsupportedTokensV0),
    }
}

fn to_trezor_account_input(
    chain_config: &ChainConfig,
    address_paths: Vec<MintlayerAddressPath>,
    outpoint: &common::chain::AccountOutPoint,
) -> SignerResult<MintlayerTxInput> {
    let mut inp_req = MintlayerAccountTxInput::new();
    inp_req.addresses = address_paths;
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
    address_paths: Vec<MintlayerAddressPath>,
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

    inp_req.addresses = address_paths;

    let mut inp = MintlayerTxInput::new();
    inp.utxo = Some(inp_req).into();
    Ok(inp)
}

struct StandaloneInput {
    multisig_idx: Option<u32>,
    private_key: PrivateKey,
}

type StandaloneInputs = BTreeMap</*input index*/ u32, Vec<StandaloneInput>>;

/// Find the derivation paths to the key in the destination, or multiple in the case of a multisig
fn destination_to_address_paths(
    key_chain: &impl AccountKeyChains,
    dest: &Destination,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<MintlayerAddressPath>, Vec<StandaloneInput>)> {
    destination_to_address_paths_impl(key_chain, dest, None, db_tx)
}

fn destination_to_address_paths_impl(
    key_chain: &impl AccountKeyChains,
    dest: &Destination,
    multisig_idx: Option<u32>,
    db_tx: &impl WalletStorageReadUnlocked,
) -> SignerResult<(Vec<MintlayerAddressPath>, Vec<StandaloneInput>)> {
    match key_chain.find_public_key(dest) {
        Some(FoundPubKey::Hierarchy(xpub)) => {
            let address_n = xpub
                .get_derivation_path()
                .as_slice()
                .iter()
                .map(|c| c.into_encoded_index())
                .collect();
            Ok((
                vec![MintlayerAddressPath {
                    address_n,
                    multisig_idx,
                    ..Default::default()
                }],
                vec![],
            ))
        }
        Some(FoundPubKey::Standalone(acc_public_key)) => {
            let standalone_input =
                db_tx.get_account_standalone_private_key(&acc_public_key)?.map(|private_key| {
                    StandaloneInput {
                        multisig_idx,
                        private_key,
                    }
                });
            Ok((vec![], standalone_input.into_iter().collect()))
        }
        None if multisig_idx.is_none() => {
            if let Some(challenge) = key_chain.find_multisig_challenge(dest) {
                let (x, y): (Vec<_>, Vec<_>) = itertools::process_results(
                    challenge.public_keys().iter().enumerate().map(|(idx, pk)| {
                        destination_to_address_paths_impl(
                            key_chain,
                            &Destination::PublicKey(pk.clone()),
                            Some(idx as u32),
                            db_tx,
                        )
                    }),
                    |iter| iter.unzip(),
                )?;

                Ok((
                    x.into_iter().flatten().collect(),
                    y.into_iter().flatten().collect(),
                ))
            } else {
                Ok((vec![], vec![]))
            }
        }
        None => Ok((vec![], vec![])),
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
) -> SignerResult<BTreeMap<TransactionId, BTreeMap<u32, MintlayerTxOutput>>> {
    let mut utxos: BTreeMap<TransactionId, BTreeMap<u32, MintlayerTxOutput>> = BTreeMap::new();

    for (utxo, inp) in ptx.input_utxos().iter().zip(ptx.tx().inputs()) {
        match inp {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo.as_ref().ok_or(SignerError::MissingUtxo)?;
                let id = match outpoint.source_id() {
                    OutPointSourceId::Transaction(id) => id.to_hash().0,
                    OutPointSourceId::BlockReward(id) => id.to_hash().0,
                };
                let out = to_trezor_output_msg(chain_config, utxo, ptx.additional_info())?;
                utxos.entry(id).or_default().insert(outpoint.output_index(), out);
            }
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => {}
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
    session_id: Vec<u8>,
}

impl std::fmt::Debug for TrezorSignerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrezorSignerProvider")
    }
}

impl TrezorSignerProvider {
    pub fn new(selected: Option<SelectedDevice>) -> Result<Self, TrezorError> {
        let (client, data, session_id) = find_trezor_device(selected)?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            data,
            session_id,
        })
    }

    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        device_id: Option<String>,
    ) -> WalletResult<Self> {
        let (client, data, session_id) = find_trezor_device_from_db(db_tx, device_id)?;

        let provider = Self {
            client: Arc::new(Mutex::new(client)),
            data,
            session_id,
        };

        check_public_keys_against_db(db_tx, &provider, chain_config)?;

        Ok(provider)
    }

    fn fetch_extended_pub_key(
        &self,
        chain_config: &Arc<ChainConfig>,
        account_index: U31,
    ) -> SignerResult<ExtendedPublicKey> {
        fetch_extended_pub_key(
            &mut self.client.lock().expect("poisoned lock"),
            chain_config,
            account_index,
        )
        .map_err(SignerError::TrezorError)
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

/// Check that the public keys in the provided key chain are the same as the ones from the
/// connected hardware wallet
fn check_public_keys_against_key_chain(
    db_tx: &impl WalletStorageReadLocked,
    client: &mut Trezor,
    trezor_data: &TrezorData,
    key_chain: &impl AccountKeyChains,
    chain_config: &ChainConfig,
) -> SignerResult<()> {
    let expected_pk = fetch_extended_pub_key(client, chain_config, key_chain.account_index())?;

    if key_chain.account_public_key() == &expected_pk {
        return Ok(());
    }

    if let Some(data) = db_tx.get_hardware_wallet_data()? {
        match data {
            HardwareWalletData::Trezor(data) => {
                // If the device_id is the same but public keys are different, maybe a
                // different passphrase was used
                if data.device_id == trezor_data.device_id {
                    return Err(TrezorError::HardwareWalletDifferentPassphrase.into());
                } else {
                    return Err(TrezorError::HardwareWalletDifferentMnemonicOrPassphrase {
                        file_device_id: data.device_id,
                        connected_device_id: trezor_data.device_id.clone(),
                        file_label: data.label,
                        connected_device_label: trezor_data.label.clone(),
                    }
                    .into());
                }
            }
        }
    }

    Err(TrezorError::HardwareWalletDifferentFile)?
}

fn fetch_extended_pub_key(
    client: &mut Trezor,
    chain_config: &ChainConfig,
    account_index: U31,
) -> Result<ExtendedPublicKey, TrezorError> {
    let derivation_path = make_account_path(chain_config, account_index);
    let account_path = derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect();
    let chain_type = to_trezor_chain_type(chain_config);
    let xpub = client
        .mintlayer_get_public_key(chain_type, account_path)
        .map_err(|e| TrezorError::DeviceError(e.to_string()))?;
    let chain_code = ChainCode::from(xpub.chain_code.0);
    let account_pubkey = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        chain_code,
        Secp256k1PublicKey::from_bytes(&xpub.public_key.serialize())
            .map_err(|_| TrezorError::InvalidKey)?,
    );
    let account_pubkey = ExtendedPublicKey::new(account_pubkey);
    Ok(account_pubkey)
}

/// Check that the public keys in the DB are the same as the ones from the connected hardware
/// wallet
fn check_public_keys_against_db(
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
    let loaded_acc =
        provider.load_account_from_database(chain_config.clone(), db_tx, &first_acc)?;

    check_public_keys_against_key_chain(
        db_tx,
        &mut provider.client.lock().expect("poisoned lock"),
        &provider.data,
        loaded_acc.key_chain(),
        &chain_config,
    )
    .map_err(WalletError::SignerError)
}

fn find_trezor_device(
    selected: Option<SelectedDevice>,
) -> Result<(Trezor, TrezorData, Vec<u8>), TrezorError> {
    let devices = find_devices(false);
    ensure!(!devices.is_empty(), TrezorError::NoDeviceFound);

    let mut devices = devices
        .into_iter()
        .filter(|device| {
            device.model == Model::Trezor
                || device.model == Model::TrezorEmulator
                || device.model == Model::TrezorLegacy
        })
        .filter_map(|d| {
            d.connect().ok().and_then(|mut c| {
                c.init_device(None).ok()?;

                c.features()?
                    .capabilities
                    .iter()
                    .filter_map(|c| c.enum_value().ok())
                    .contains(&Capability::Capability_Mintlayer)
                    .then_some(c)
            })
        })
        .collect_vec();

    let found_selected_device = selected.as_ref().and_then(|s| {
        devices
            .iter()
            .position(|d| d.features().is_some_and(|f| s.device_id == f.device_id()))
    });

    let client = if let Some(position) = found_selected_device {
        devices.remove(position)
    } else {
        match devices.len() {
            0 => return Err(TrezorError::NoCompatibleDeviceFound),
            1 => devices.remove(0),
            _ => {
                let devices = devices
                    .into_iter()
                    .filter_map(|c| {
                        c.features().map(|f| FoundDevice {
                            name: if !f.label().is_empty() {
                                f.label()
                            } else {
                                f.model()
                            }
                            .to_owned(),
                            device_id: f.device_id().to_owned(),
                        })
                    })
                    .collect();
                return Err(TrezorError::NoUniqueDeviceFound(devices));
            }
        }
    };

    let features = client.features().ok_or(TrezorError::CannotGetDeviceFeatures)?;
    let data = TrezorData {
        label: features.label().to_owned(),
        device_id: features.device_id().to_owned(),
    };
    let session_id = features.session_id().to_vec();

    Ok((client, data, session_id))
}

impl SignerProvider for TrezorSignerProvider {
    type S = TrezorSigner;
    type K = AccountKeyChainImplHardware;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, _account_index: U31) -> Self::S {
        TrezorSigner::new(chain_config, self.client.clone(), self.session_id.clone())
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

    fn get_hardware_wallet_data(&self) -> Option<HardwareWalletData> {
        Some(HardwareWalletData::Trezor(self.data.clone()))
    }
}

fn single_signature(
    signatures: &[MintlayerSignature],
) -> Result<Option<&MintlayerSignature>, TrezorError> {
    match signatures {
        [] => Ok(None),
        [single] => {
            ensure!(
                single.multisig_idx.is_none(),
                TrezorError::MultisigSignatureReturned
            );
            Ok(Some(single))
        }
        _ => Err(TrezorError::MultipleSignaturesReturned),
    }
}

fn is_htlc_utxo(utxo: &TxOutput) -> bool {
    match utxo {
        TxOutput::Htlc(_, _) => true,

        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => false,
    }
}

#[cfg(feature = "enable-trezor-device-tests")]
#[cfg(test)]
mod tests;

#[cfg(feature = "enable-trezor-device-tests")]
#[cfg(test)]
pub mod test_utils;
